"""Run the local HTTP middleware using a fixed loopback binding."""
import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    uvicorn.run('security_middleware.api:create_app', factory=True,
                host='127.0.0.1', port=args.port, access_log=False)


if __name__ == '__main__':
    main()
