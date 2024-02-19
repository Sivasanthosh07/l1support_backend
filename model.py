

import json
from os import environ
from langchain.agents.agent_types import AgentType
from langchain_openai import ChatOpenAI, OpenAI
from langchain_experimental.agents.agent_toolkits.pandas.base import    create_pandas_dataframe_agent
from langchain.document_loaders import TextLoader
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.vectorstores import Chroma
from langchain.embeddings.sentence_transformer import SentenceTransformerEmbeddings
from langchain.document_loaders.csv_loader import CSVLoader
from okta_helper import get_okta_logs
import requests
model_url = "https://us-south.ml.cloud.ibm.com/ml/v1-beta/generation/text?version=2023-05-29"
token_url="https://iam.cloud.ibm.com/identity/token"
api_key=environ.get("API_KEY")
def ask_logs(username,question):
    try:
        dataframes=get_okta_logs(username)
        print(dataframes)
        agent_open = create_pandas_dataframe_agent(ChatOpenAI(temperature=0, model="gpt-3.5-turbo-1106",api_key=api_key), dataframes, verbose=True, max_iterations=600,            
                                         max_execution_time=600,agent_type=AgentType.OPENAI_FUNCTIONS
                                     )
        ans=agent_open.run(question)  
        return [ans]   
    except Exception as e:
        return json.dumps({'error':str(e)}),500


def get_token():
        print(api_key, "*******************")
        token_response = requests.post(token_url, data={
                                       "apikey": api_key, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
        token = token_response.json()["access_token"]
        return token
