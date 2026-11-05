/**
 * Limits for the document ingest pipeline.
 *
 * They live in one place so the size gate, the sanitizers and whatever endpoint
 * ends up calling them all quote the same numbers instead of drifting apart.
 */

/** Largest upload accepted, checked before a single byte is parsed (10 MiB). */
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

/** Smallest upload accepted: below it, nothing can be a real image header. */
export const MIN_UPLOAD_BYTES = 100;

/** Longest side of an image, in pixels. */
export const MAX_IMAGE_DIMENSION = 10_000;

/**
 * Largest number of pixels. The pixel count is what a decoder allocates, so it
 * is capped separately from the file size: a small file can describe a canvas
 * that is far too big to render.
 */
export const MAX_IMAGE_PIXELS = 40_000_000;
