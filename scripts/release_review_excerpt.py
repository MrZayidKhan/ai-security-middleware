"""Print one approved local excerpt with provenance; never call a model."""
import argparse
from pathlib import Path

from security_middleware.review_queue import ReviewQueue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('review_id', type=int)
    parser.add_argument('--database', type=Path,
        default=Path(__file__).resolve().parents[1]/'runtime_data'/'reviews.db')
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error('Review database does not exist. Start the local dashboard first.')
    try:
        approved = ReviewQueue(args.database).approved_content(args.review_id)
    except ValueError as error:
        parser.error(str(error))
    print(approved.model_dump_json(indent=2))


if __name__ == '__main__':
    main()
