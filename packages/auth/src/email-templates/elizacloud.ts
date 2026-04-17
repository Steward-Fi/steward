import type { MagicLinkTemplateData, RenderedMagicLinkTemplate } from "./default";
import { renderDefaultTemplate } from "./default";

export function renderElizaCloudTemplate(
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  // TODO: replace with Eliza Cloud branded copy and HTML.
  return renderDefaultTemplate(data);
}
