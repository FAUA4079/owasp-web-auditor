"""Bounded, heuristic reflection context; retains no body, marker or attribute names."""
from html.parser import HTMLParser

MAX_CHARS = 200_000
MAX_OCCURRENCES = 20


class _ContextParser(HTMLParser):
    def __init__(self, marker):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.count = 0
        self.contexts = set()
        self.raw_tag = None

    def record(self, value, context):
        hits = value.count(self.marker)
        if hits:
            self.contexts.add(context)
            self.count = min(MAX_OCCURRENCES, self.count + hits)

    def handle_starttag(self, tag, attrs):
        self.record(tag, 'tag_name')
        for name, value in attrs:
            self.record(name, 'attribute_name')
            if value:
                self.record(value, 'html_attribute')
        if tag in ('script', 'style'):
            self.raw_tag = tag

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.raw_tag = None

    def handle_endtag(self, tag):
        self.record(tag, 'tag_name')
        if tag == self.raw_tag:
            self.raw_tag = None

    def handle_data(self, data):
        context = {'script': 'script_text', 'style': 'style_text'}.get(self.raw_tag, 'html_text')
        self.record(data, context)

    def handle_comment(self, data):
        self.record(data, 'html_comment')


def classify_reflection(body, marker, media_type):
    # UTF-8 is a heuristic here, just as in the existing disclosure check.
    text = body[:MAX_CHARS * 4].decode('utf-8', errors='replace')
    limited = len(body) > MAX_CHARS * 4 or len(text) > MAX_CHARS
    text = text[:MAX_CHARS]
    raw_hits = text.count(marker)
    contexts = set()
    state = 'classified'
    if media_type == 'text/plain':
        if raw_hits:
            contexts.add('plain_text')
    elif media_type in ('text/html', 'application/xhtml+xml'):
        parser = _ContextParser(marker)
        try:
            parser.feed(text)
            parser.close()
            contexts = parser.contexts
            if raw_hits > parser.count:
                contexts.add('unclassified')
        except (ValueError, AssertionError, RecursionError):
            contexts = {'unclassified'} if raw_hits else set()
            state = 'parser_failed'
    else:
        return {'state': 'unsupported', 'contexts': [], 'occurrences_in_prefix': 0,
                'inspection_limited': limited, 'occurrence_limit_reached': False}
    if not raw_hits:
        contexts = set()
        state = 'not_observed_in_prefix'
    return {'state': state, 'contexts': sorted(contexts),
            'occurrences_in_prefix': min(raw_hits, MAX_OCCURRENCES),
            'inspection_limited': limited,
            'occurrence_limit_reached': raw_hits >= MAX_OCCURRENCES}
