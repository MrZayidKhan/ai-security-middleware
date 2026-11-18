"""Run the local HTTP middleware using a fixed loopback binding."""
import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--detector',choices=['existing','english-verifier'],default='existing',
                        help='Opt-in English semantic verifier; existing remains the default.')
    args = parser.parse_args()
    if args.detector=='english-verifier':
        from security_middleware.api import create_app
        from security_middleware.content_protection import ContentInspector
        from security_middleware.verified_detector import VerifiedDetector
        app=create_app(inspector=ContentInspector(detector=VerifiedDetector()),detector_label='rules+english-contextual-verifier')
        uvicorn.run(app,host='127.0.0.1',port=args.port,access_log=False)
    else:
        uvicorn.run('security_middleware.api:create_app',factory=True,
                    host='127.0.0.1',port=args.port,access_log=False)


if __name__ == '__main__':
    main()
