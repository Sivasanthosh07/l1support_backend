## Helpdesk User Risk Assessment 

### Run Backend App Locally
Make sure you have Python installed already.
- Clone repository and change directory to it.
- Create virtual environment and activate.
```bash
cd backend/
python -m venv venv
source venv/bin/activate
```
- Rename and update the environment file
```bash
mv .env.example .env
``` 
- Install dependencies
```bash
pip install -r requirements.txt
```
- Run the app.
```bash
export FLASK_APP=app.py
flask run --debug
```
