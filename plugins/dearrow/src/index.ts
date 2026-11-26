// @description Replaces YouTube titles and thumbnails in embeds using DeArrow
// @version 0.1.3
// @author amaanq

const { gateway } = phoenix;

const settings = phoenix.settings.define({
  titles: {
    type: "switch",
    title: "Replace titles",
    description: "Use crowdsourced titles from DeArrow",
    default: true,
  },
  thumbnails: {
    type: "switch",
    title: "Replace thumbnails",
    description: "Use crowdsourced thumbnails from DeArrow",
    default: true,
  },
});

interface Branding {
  titles: { title: string; original: boolean; votes: number; locked: boolean }[];
  thumbnails: { timestamp: number | null; original: boolean; votes: number; locked: boolean }[];
}

interface Replacement {
  title?: string;
  thumbnail?: string;
}

const cache = new Map<string, Promise<Replacement>>();
/// Finished lookups, which a `before` hook can read without waiting.
const resolved = new Map<string, Replacement>();

const VIDEO = /(?:youtube\.com\/(?:watch\?(?:.*&)?v=|shorts\/)|youtu\.be\/)([\w-]{11})/;

const videoId = (url: string | undefined) => url?.match(VIDEO)?.[1];

/// Every video a message links to, in its text or its embeds.
const videosIn = (message: Phoenix.GatewayMessage) => {
  const ids = new Set<string>();
  for (const match of (message.content ?? "").matchAll(new RegExp(VIDEO, "g"))) ids.add(match[1]);
  for (const embed of message.embeds ?? []) {
    const id = videoId(embed.url);
    if (id) ids.add(id);
  }
  return ids;
};

const trusted = (entry: { original: boolean; votes: number; locked: boolean }) =>
  !entry.original && (entry.votes >= 0 || entry.locked);

const lookup = (id: string) => {
  let pending = cache.get(id);
  if (!pending) {
    pending = phoenix
      .fetch(`https://sponsor.ajay.app/api/branding?videoID=${id}`)
      .then((response) => {
        if (!response.ok) return {};
        const branding = response.json<Branding>();
        const title = branding.titles.find(trusted)?.title.replace(/(^|\s)>(\S)/g, "$1$2");
        const thumbnail = branding.thumbnails.find(trusted);
        const result: Replacement = {
          title,
          thumbnail:
            thumbnail?.timestamp == null
              ? undefined
              : `https://dearrow-thumb.ajay.app/api/v1/getThumbnail?videoID=${id}&time=${thumbnail.timestamp}`,
        };
        resolved.set(id, result);
        if (resolved.size > 512) resolved.delete(resolved.keys().next().value!);
        return result;
      })
      .catch((err) => {
        cache.delete(id);
        phoenix.log.warn(`dearrow ${id}: ${err}`);
        return {};
      });
    // One entry per video seen, so drop the oldest past a few hundred.
    if (cache.size >= 512) cache.delete(cache.keys().next().value!);
    cache.set(id, pending);
  }
  return pending;
};

type Embed = NonNullable<Phoenix.GatewayMessage["embeds"]>[number];

/// Rewrites `embed` in place from `replacement`, and says whether it changed.
const apply = (embed: Embed, { title, thumbnail }: Replacement) => {
  let changed = false;
  if (title && settings.titles && embed.title !== title) {
    embed.title = title;
    changed = true;
  }
  if (thumbnail && settings.thumbnails && embed.thumbnail && embed.thumbnail.url !== thumbnail) {
    embed.thumbnail = { ...embed.thumbnail, url: thumbnail, proxy_url: thumbnail };
    changed = true;
  }
  return changed;
};

/// Rewrites `embeds` in place, waiting for lookups, and says whether anything changed.
const rebrandEmbeds = async (embeds: Phoenix.GatewayMessage["embeds"]) => {
  let changed = false;
  for (const embed of embeds ?? []) {
    const id = videoId(embed.url);
    if (id && apply(embed, await lookup(id))) changed = true;
  }
  return changed;
};

const rebrand = async (message: Phoenix.GatewayMessage) => {
  const embeds = message.embeds;
  if (!(await rebrandEmbeds(embeds))) return;
  // The whole message: Desktop's handler skips an update that is only the
  // changed fields.
  phoenix.enqueue(gateway.messageUpdate, { ...message, embeds });
};

// A new message's embed usually arrives a moment later in an update, so its
// links are looked up as soon as the message does, and the embed is rewritten
// before the client stores it. Links still being looked up fall back to an
// update once the lookup ends.
const rewrite = {
  before(message: Phoenix.GatewayMessage) {
    for (const id of videosIn(message)) if (!resolved.has(id)) lookup(id);
    for (const embed of message.embeds ?? []) {
      const known = resolved.get(videoId(embed.url) ?? "");
      if (known) apply(embed, known);
    }
    return message;
  },
};
phoenix.hook(gateway.messageCreate, rewrite);
phoenix.hook(gateway.messageUpdate, rewrite);
phoenix.on(gateway.messageCreate, rebrand);
phoenix.on(gateway.messageUpdate, rebrand);

// Desktop gets a link's embed with the channel's history rather than a
// gateway update, so the reply is rebranded too.
if (typeof (phoenix as { bridge?: unknown }).bridge === "undefined") {
  phoenix.discord.onResponse(
    { method: "GET", pathPrefix: "/channels/", pathSuffix: "/messages" },
    async (res) => {
      if (res.status < 200 || res.status >= 300) return;
      const list = res.json<unknown>();
      if (!Array.isArray(list)) return;
      const changed = await Promise.all(
        list.map((message) => rebrandEmbeds((message as Phoenix.GatewayMessage).embeds)),
      );
      if (changed.some(Boolean)) return { body: JSON.stringify(list) };
    },
  );
}
