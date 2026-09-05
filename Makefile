test:
	pytest -q
	python scripts/evaluate.py

api:
	uvicorn api:app --reload

web:
	npm run dev --workspace=regops-eu-command-center
