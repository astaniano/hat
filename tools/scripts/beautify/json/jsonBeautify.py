import json
import sys

def beautify_json(json_string):
    try:
        # Parse the JSON string
        json_object = json.loads(json_string)
        
        # Beautify the JSON with a 2-space indentation
        beautified_json = json.dumps(json_object, indent=2)
        
        # Return the beautified JSON
        return beautified_json
    except json.JSONDecodeError as error:
        print('Invalid JSON string:', error.msg)

if __name__ == "__main__":
    # Get the JSON string from command line arguments
    json_string = sys.argv[1] if len(sys.argv) > 1 else None

    # Call the function with the provided JSON
    if json_string:
        result = beautify_json(json_string)
        print(result)
    else:
        print('Please provide a JSON string as an argument.')

