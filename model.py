

import json
from os import environ
from langchain.document_loaders import TextLoader
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.vectorstores import Chroma
from langchain.embeddings.sentence_transformer import SentenceTransformerEmbeddings
from langchain.document_loaders.csv_loader import CSVLoader
import requests
model_url = "https://us-south.ml.cloud.ibm.com/ml/v1-beta/generation/text?version=2023-05-29"
token_url="https://iam.cloud.ibm.com/identity/token"
api_key=environ.get("API_KEY")
def ask_logs(name,question):
    try:
        # loader = CSVLoader("filtered.csv")
        # documents = loader.load()
        # text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
        # texts = text_splitter.split_documents(documents)
        embedding_function = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
        # docsearch = Chroma.from_documents(texts, embeddings,persist_directory='./vector_db_store/'+name) 
        from ibm_watson_machine_learning.metanames import GenTextParamsMetaNames as GenParams
        from ibm_watson_machine_learning.foundation_models.utils.enums import DecodingMethods
        from ibm_watson_machine_learning.foundation_models.utils.enums import ModelTypes

        model_id = ModelTypes.FLAN_UL2
        parameters = {
            GenParams.DECODING_METHOD: DecodingMethods.GREEDY,
            GenParams.MIN_NEW_TOKENS: 1,
            GenParams.MAX_NEW_TOKENS: 100
        }
        credentials = {
            "url": "https://us-south.ml.cloud.ibm.com",
            "apikey": api_key
        }
        from ibm_watson_machine_learning.foundation_models import Model

        model = Model(
            model_id=model_id,
            params=parameters,
            credentials=credentials,
            project_id="7bbc5839-0882-4a11-a5a0-d74a760a02d6"
        )
        from ibm_watson_machine_learning.foundation_models.extensions.langchain import WatsonxLLM

        llama = WatsonxLLM(model=model)
        from langchain.chains import RetrievalQA


        vectordb = Chroma(persist_directory='/home/sivasanthosh/Desktop/usecases/helpdesk-user-risk-assessment/backend/chroma_db', embedding_function=embedding_function)
        qa = RetrievalQA.from_chain_type(llm=llama, chain_type="stuff", retriever=vectordb.as_retriever())
        # qa = RetrievalQA.from_chain_type(llm=flan_ul2_llm, chain_type="stuff", retriever=docsearch.as_retriever())
        query = question+"give only the answer."

        ans=qa.run(query)  
        return [ans]   
    except Exception as e:
        return json.dumps({'error':str(e)}),500
# print(ask_logs("filtered_csv_bot","what is the latest login time of suvarna sawai"))
# print(ask_logs("filtered_csv_bot","give the  actor display names"))
# give the  email id of suvarna



def get_token():
        print(api_key, "*******************")
        token_response = requests.post(token_url, data={
                                       "apikey": api_key, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
        token = token_response.json()["access_token"]
        return token
