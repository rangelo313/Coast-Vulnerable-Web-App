FROM python:3.8.5

ENV USERNAME=usr
RUN useradd usr
RUN mkdir -p /home/${USERNAME}/app && chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/app

WORKDIR /home/${USERNAME}/app

ENV FLASK_APP run.py

COPY . .

RUN mkdir -p ./app/base/static/files
RUN tar -c --exclude-from=.gitignore -vzf ../coast-admin-source.tar.gz ./ && mv ../coast-admin-source.tar.gz ./app/base/static/files
RUN (test -f .env.secret.prod && cat .env.public .env.secret.prod > .env) || true

RUN pip install -r requirements.txt

EXPOSE 5005
CMD ["gunicorn", "--config", "gunicorn-cfg.py", "run:app"]
# gunicorn --config gunicorn-cfg.py run:app
