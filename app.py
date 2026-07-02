from llm.model import create_llm, test_llm

def main():
    """
    Main function to create and test the LLM.
    """

    # Create the LLM
    llm = create_llm()

    # Test the LLM
    response = test_llm(llm)
    print("LLM Response:", response)

if __name__ == "__main__":
    main()