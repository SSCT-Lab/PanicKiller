from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def calculate_similarity_for_single_pair(panic_info, pattern):
    """
    Calculates the similarity score between a single pair of panic information and a pattern.

    Parameters:
    - panic_info: A string representing the panic message.
    - pattern: A string representing the description of a fix pattern.

    Returns:
    - A floating-point number representing the similarity score.
    """
    # Create a TF-IDF Vectorizer
    vectorizer = TfidfVectorizer()

    # Transform the texts into TF-IDF feature vectors
    tfidf_matrix = vectorizer.fit_transform([panic_info, pattern])

    # Calculate the cosine similarity between the first text (panic_info) and the second text (pattern)
    similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])

    # similarity is a 1x1 matrix, extract its value as a float to return
    return similarity[0][0]
