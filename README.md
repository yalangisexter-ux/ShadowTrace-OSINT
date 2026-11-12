# ShadowTrace OSINT

Privacy-conscious OSINT workspace for investigating public usernames across a curated set of public websites. Candidate matches are not proof of identity. No private-account access, authentication bypass, breached datasets, or arbitrary URL fetching.

## Local development
Python 3.11+: `pip install -r requirements.txt && uvicorn app.main:app --reload`

## Render
Connect this repository as a Blueprint using `render.yaml`. Set `DATABASE_URL` to a Render PostgreSQL internal URL and set a long random `SECRET_KEY`. Never commit secrets.
