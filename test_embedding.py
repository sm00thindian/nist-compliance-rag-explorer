import sys
sys.path.insert(0, 'src')
from config_loader import get_config
from embedding_manager import EmbeddingManager

# Test the new system
config = get_config()
embedding_config = config.get_embedding_config()
print('Testing new embedding system...')
print(f'Model: {embedding_config["model_name"]}')
print(f'Dimensions: {embedding_config["dimensions"]}')
print(f'Similarity: {embedding_config["similarity_metric"]}')

manager = EmbeddingManager(embedding_config)
info = manager.get_model_info()
print(f'Model loaded: {info["model_name"]} ({info["dimensions"]}D)')
print(f'Device: {info["device"]}')
print(f'Status: {info["status"]}')

# Test encoding
test_texts = ['Access control implementation', 'Audit log requirements']
embeddings = manager.encode(test_texts)
print(f'Encoded {len(test_texts)} texts to {embeddings.shape} embeddings')

# Test search
from retriever import build_vector_store, retrieve_relevant_docs
print('Testing vector store integration...')