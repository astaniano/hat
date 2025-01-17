import xml.etree.ElementTree as ET
import os

def beautify_xml(xml_string):
    element = ET.XML(xml_string)
    ET.indent(element)
    return ET.tostring(element, encoding='unicode')

def write_to_file_in_parent_directory(content, filename):
    current_dir = os.getcwd()
    parent_dir = os.path.dirname(current_dir)
    file_path = os.path.join(parent_dir, filename)
    
    # Open the file (it will be created if it doesn't exist, or overwritten if it does)
    with open(file_path, 'w') as file:
        file.write(content)
    
    print(f"Content has been written to: {file_path}")

xml_string = """

"""

beautified_xml = beautify_xml(xml_string)

write_to_file_in_parent_directory(xml_string, "beautified.txt")

