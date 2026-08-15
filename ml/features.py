import pefile
import numpy as np
import math

def extract_features(filepath):
    """Extract PE features matching the Ember dataset format."""
    features = {}
    try:
        pe = pefile.PE(filepath)

        # General features
        with open(filepath, 'rb') as f:
            raw = f.read()
        features['general.size'] = len(raw)
        features['general.vsize'] = pe.OPTIONAL_HEADER.SizeOfImage

        # Header features
        features['header.coff.timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['header.optional.subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['header.optional.dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['header.optional.magic'] = pe.OPTIONAL_HEADER.Magic

        # Section features
        sections = pe.sections
        features['section.count'] = len(sections)

        entropy_list = []
        for section in sections:
            data = section.get_data()
            if data:
                entropy_list.append(shannon_entropy(data))

        features['section.entropy.mean'] = np.mean(entropy_list) if entropy_list else 0
        features['section.entropy.std'] = np.std(entropy_list) if entropy_list else 0
        features['section.entropy.min'] = np.min(entropy_list) if entropy_list else 0
        features['section.entropy.max'] = np.max(entropy_list) if entropy_list else 0

        # Import features
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['import.count'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            dlls = [entry.dll.decode('utf-8', errors='ignore').lower() 
                   for entry in pe.DIRECTORY_ENTRY_IMPORT]
            features['import.dlls'] = dlls
        else:
            features['import.count'] = 0
            features['import.dlls'] = []

    except Exception:
        features = {
            'general.size': 0, 'general.vsize': 0, 'header.coff.timestamp': 0,
            'header.optional.subsystem': 0, 'header.optional.dll_characteristics': 0,
            'header.optional.magic': 0, 'section.count': 0, 'section.entropy.mean': 0,
            'section.entropy.std': 0, 'section.entropy.min': 0, 'section.entropy.max': 0,
            'import.count': 0, 'import.dlls': []
        }

    return features

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
