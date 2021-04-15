Instructions for running the code locally if you like. Shouldn't be necessary to find the flags, but may be helpful, depending on your work style. 

Setup TLS certificates (optional): 
Testing with security keys requires TLS certificates for WebAuthN. You can setup some certs for local development using [mkcert](https://github.com/FiloSottile/mkcert). Everything else should work without TLS, though. 

# Without docker
```
# Setup
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
cat .env.public .env.secret.dummy > .env

export FLASK_APP=run.py 
export FLASK_ENV=development 

# Run without TLS
flask run --host=0.0.0.0 --port=5000

# Run with TLS
flask run --host=0.0.0.0 --port=5000  --cert=localhost.pem --key=localhost-key.pem
```

# With docker
```
docker build -t coast-admin .
docker run -dp 5000:5005 coast-admin
```
# Codigo
