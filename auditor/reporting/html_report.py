"""Offline Jinja report. Target content is data, never template source."""
import argparse
import html
import json
import os
import tempfile
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup
from auditor.reporting.validation import load_report_data


def escaped_text(value):
    # Match the existing escaping contract, including &quot;.
    return Markup(html.escape(str(value), quote=True))


def render_report(run_dir, *, privacy=False):
    data = load_report_data(run_dir)
    from auditor.reporting.ai import report_view
    data["ai"] = report_view(run_dir)
    from auditor.review.generate import review_view
    data["ai_review"] = review_view(run_dir)
    if privacy:
        from auditor.reporting.phase6 import redact
        data = redact(data)
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'),
                      autoescape=True, undefined=StrictUndefined)
    env.filters['text'] = escaped_text
    env.filters['pretty_json'] = lambda value: json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)
    data['counts'] = {status: sum(t['status'] == status for t in data['tests']) for status in
                      ('Confirmed', 'Potential', 'Inconclusive', 'No Issue Observed', 'Not Tested')}
    return env.get_template('report.html').render(**data)


def write_report(run_dir, *, privacy=False, output=None):
    run_dir = Path(run_dir)
    document = render_report(run_dir, privacy=privacy)
    if privacy and output is None:
        raise ValueError('Privacy export requires an explicit destination')
    output = Path(output) if output is not None else run_dir / 'reports/report.html'
    output.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent,
                                         prefix='.report-', suffix='.tmp', delete=False) as handle:
            name = handle.name
            handle.write(document)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, output)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)
    return output


def main():
    parser = argparse.ArgumentParser(description='Generate report and automatic English AI explanations; no target requests sent.')
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument("--refresh-ai", action="store_true", help="Regenerate AI explanations and evidence reviews")
    from auditor.reporting.ai import add_ai_arguments, apply_ai_arguments
    add_ai_arguments(parser)
    args = parser.parse_args()
    apply_ai_arguments(args)
    try:
        import asyncio
        from auditor.resume_engine import lock_run
        from auditor.reporting.ai import ensure_all_ai
        with lock_run(args.run):
            output = write_report(args.run)
            asyncio.run(ensure_all_ai(args.run, force=args.refresh_ai))
    except KeyboardInterrupt:
        parser.exit(130, "AI interrupted; saved results and completed explanations retained.\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Could not generate report: {exc}\n')
    print(f'Report created: {output.resolve()}')

if __name__ == '__main__':
    main()
