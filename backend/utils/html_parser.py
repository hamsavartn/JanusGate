"""HTML Parser for extracting plaintext and markdown links from emails."""

from html.parser import HTMLParser
import re

class EmailHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.extracted_parts = []
        self._current_href = None
        self._ignore_tags = {'script', 'style', 'head', 'title', 'meta', 'link'}
        self._ignore_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._ignore_tags:
            self._ignore_depth += 1
            return

        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href':
                    self._current_href = value
                    self.extracted_parts.append('[')
                    break
        elif tag in {'br', 'p', 'div', 'tr', 'li'}:
            self.extracted_parts.append('\n')

    def handle_endtag(self, tag):
        if tag in self._ignore_tags:
            self._ignore_depth = max(0, self._ignore_depth - 1)
            return

        if tag == 'a' and self._current_href is not None:
            self.extracted_parts.append(f']({self._current_href})')
            self._current_href = None
        elif tag in {'p', 'div', 'tr', 'li'}:
            self.extracted_parts.append('\n')

    def handle_data(self, data):
        if self._ignore_depth > 0:
            return
        cleaned = data.strip()
        if cleaned:
            self.extracted_parts.append(data)

def extract_text(html_content: str) -> str:
    """Extracts text from HTML, preserving links as Markdown [text](url)."""
    if not html_content or '<' not in html_content or '>' not in html_content:
        return html_content  # Probably just plaintext already
        
    parser = EmailHTMLParser()
    try:
        parser.feed(html_content)
        parser.close()
        text = "".join(parser.extracted_parts)
        # Collapse excessive newlines
        return re.sub(r'\n{3,}', '\n\n', text).strip()
    except Exception:
        # Fallback to returning raw if parsing fails for some reason
        return html_content
