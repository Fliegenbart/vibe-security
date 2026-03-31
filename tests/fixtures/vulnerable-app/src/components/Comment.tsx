export function Comment({ html }: { html: string }) {
  // XSS vulnerability - should be caught
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
