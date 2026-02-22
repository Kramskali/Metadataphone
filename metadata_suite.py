#!/usr/bin/env python3
"""
Metadata Forensics Suite for Termux
====================================
A comprehensive tool for metadata extraction, spoofing, and forensic analysis.
Designed for Android/Termux environments with Python 3.

Components:
    - collect: Extract metadata from images, files, and network
    - spoof: Edit and forge metadata (EXIF, timestamps)
    - verify: Forensic analysis to detect tampering
    - phone: Cell tower and WiFi metadata analysis

Usage:
    python metadata_suite.py collect -i image.jpg
    python metadata_suite.py spoof -i image.jpg --gps "40.7128,-74.0060"
    python metadata_suite.py verify -i image.jpg
    python metadata_suite.py phone --cell-info

Author: Open Source Forensics Education
License: MIT
"""

import argparse
import json
import os
import sys
import hashlib
import time
import datetime
import re
import struct
import math
import io
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies with fallbacks
try:
    from PIL import Image, ExifTags, TiffImagePlugin
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# =============================================================================
# CONSTANTS AND ENUMS
# =============================================================================

class VerificationResult(Enum):
    REAL = "REAL"
    SUSPICIOUS = "SUSPICIOUS"
    FAKE = "FAKE"

@dataclass
class ForensicFinding:
    category: str
    check: str
    result: str
    confidence: float
    details: Dict[str, Any]

@dataclass
class VerificationReport:
    overall_result: VerificationResult
    confidence_score: float
    findings: List[ForensicFinding]
    metadata_summary: Dict[str, Any]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_json(data: Dict, pretty: bool = True):
    """Print data as formatted JSON."""
    if pretty:
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    else:
        print(json.dumps(data, default=str, ensure_ascii=False))

def calculate_hash(filepath: str, algorithm: str = 'sha256') -> str:
    """Calculate file hash."""
    hash_obj = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def format_bytes(size: int) -> str:
    """Format bytes to human readable."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def gps_to_decimal(degrees: Tuple, direction: str) -> float:
    """Convert GPS coordinates to decimal degrees.
    
    Args:
        degrees: Tuple of ((deg_num, deg_den), (min_num, min_den), (sec_num, sec_den))
                or (degrees, minutes, seconds) as floats
        direction: 'N', 'S', 'E', or 'W'
    """
    if not degrees:
        return None
    
    # Handle EXIF format with rationals: ((d,1), (m,1), (s,1))
    if isinstance(degrees[0], tuple):
        d = float(degrees[0][0]) / float(degrees[0][1]) if degrees[0][1] != 0 else 0
        m = float(degrees[1][0]) / float(degrees[1][1]) if degrees[1][1] != 0 else 0
        s = float(degrees[2][0]) / float(degrees[2][1]) if degrees[2][1] != 0 else 0
    else:
        # Handle simple float format
        d = float(degrees[0])
        m = float(degrees[1])
        s = float(degrees[2])
    
    decimal = d + m/60 + s/3600
    if direction in ['S', 'W']:
        decimal = -decimal
    return decimal

def decimal_to_gps(decimal: float) -> Tuple:
    """Convert decimal degrees to GPS tuple."""
    direction = 'N' if decimal >= 0 else 'S'
    if decimal < 0:
        decimal = -decimal
    degrees = int(decimal)
    minutes = int((decimal - degrees) * 60)
    seconds = round(((decimal - degrees) * 60 - minutes) * 60, 3)
    return ((degrees, 1), (minutes, 1), (int(seconds * 1000), 1000)), direction


# =============================================================================
# METADATA COLLECTOR
# =============================================================================

class MetadataCollector:
    """Extract metadata from images, files, and network interfaces."""
    
    def __init__(self):
        self.results = {}
    
    def collect_all(self, filepath: str, include_network: bool = True) -> Dict:
        """Collect all available metadata."""
        result = {
            'source_file': filepath,
            'collection_time': datetime.datetime.now().isoformat(),
            'exif_data': self.extract_exif(filepath) if PIL_AVAILABLE else None,
            'filesystem_metadata': self.extract_filesystem_metadata(filepath),
            'file_hashes': self.calculate_hashes(filepath),
            'network_metadata': self.extract_network_metadata() if include_network else None
        }
        return result
    
    def extract_exif(self, filepath: str) -> Dict:
        """Extract EXIF metadata from image."""
        if not PIL_AVAILABLE:
            return {'error': 'PIL not installed. Run: pip install Pillow'}
        
        try:
            img = Image.open(filepath)
            exif_data = {}
            
            # Basic image info
            exif_data['format'] = img.format
            exif_data['mode'] = img.mode
            exif_data['size'] = img.size
            exif_data['width'] = img.width
            exif_data['height'] = img.height
            
            # EXIF data
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                exif_dict = {}
                
                for tag_id, value in exif.items():
                    tag_name = TAGS.get(tag_id, f"Unknown_{tag_id}")
                    
                    # Handle binary data
                    if isinstance(value, bytes):
                        value = f"<binary:{len(value)} bytes>"
                    
                    exif_dict[tag_name] = {
                        'tag_id': tag_id,
                        'value': str(value)[:500],  # Truncate long values
                        'raw_value': value if isinstance(value, (int, float)) else None
                    }
                
                exif_data['tags'] = exif_dict
                
                # Extract GPS info
                gps_info = self._extract_gps_info(exif)
                if gps_info:
                    exif_data['gps'] = gps_info
                
                # Extract thumbnail info
                thumbnail = self._extract_thumbnail_info(img)
                if thumbnail:
                    exif_data['thumbnail'] = thumbnail
                    
            else:
                exif_data['tags'] = {}
            
            # Extract ICC profile
            if 'icc_profile' in img.info:
                icc = img.info['icc_profile']
                exif_data['icc_profile'] = {
                    'size': len(icc),
                    'md5': hashlib.md5(icc).hexdigest()[:16]
                }
            
            img.close()
            return exif_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_gps_info(self, exif: Dict) -> Dict:
        """Extract GPS coordinates from EXIF."""
        gps_info = {}
        
        for tag_id, value in exif.items():
            tag_name = TAGS.get(tag_id, '')
            if tag_name == 'GPSInfo' and isinstance(value, dict):
                gps_data = {}
                lat = None
                lon = None
                
                for gps_tag_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPS_{gps_tag_id}")
                    gps_data[gps_tag_name] = str(gps_value)
                    
                    if gps_tag_name == 'GPSLatitude':
                        lat = gps_value
                    elif gps_tag_name == 'GPSLatitudeRef':
                        lat_ref = gps_value
                    elif gps_tag_name == 'GPSLongitude':
                        lon = gps_value
                    elif gps_tag_name == 'GPSLongitudeRef':
                        lon_ref = gps_value
                
                # Convert to decimal
                try:
                    if lat and lon:
                        lat_dec = gps_to_decimal(lat, lat_ref)
                        lon_dec = gps_to_decimal(lon, lon_ref)
                        gps_data['LatitudeDecimal'] = lat_dec
                        gps_data['LongitudeDecimal'] = lon_dec
                        gps_data['GoogleMapsURL'] = f"https://maps.google.com/?q={lat_dec},{lon_dec}"
                except:
                    pass
                
                gps_info = gps_data
                break
        
        return gps_info
    
    def _extract_thumbnail_info(self, img: Image.Image) -> Dict:
        """Extract thumbnail information from image."""
        thumbnail_info = {}
        
        try:
            # Check for embedded thumbnail
            if hasattr(img, 'app') and img.app:
                for marker, data in img.app.items():
                    if b'JFIF' in data or b'JFXX' in data:
                        thumbnail_info['type'] = 'JFIF/JFXX'
                        break
            
            # Try to extract thumbnail via piexif
            if PIEXIF_AVAILABLE:
                exif_dict = piexif.load(img.info.get('exif', b''))
                if exif_dict and 'thumbnail' in exif_dict:
                    thumb = exif_dict['thumbnail']
                    if thumb:
                        thumbnail_info['present'] = True
                        thumbnail_info['size'] = len(thumb)
                        thumbnail_info['md5'] = hashlib.md5(thumb).hexdigest()
                        
                        # Try to get thumbnail dimensions
                        try:
                            thumb_img = Image.open(io.BytesIO(thumb))
                            thumbnail_info['dimensions'] = (thumb_img.width, thumb_img.height)
                            thumb_img.close()
                        except:
                            pass
                else:
                    thumbnail_info['present'] = False
            
        except Exception as e:
            thumbnail_info['error'] = str(e)
        
        return thumbnail_info
    
    def extract_filesystem_metadata(self, filepath: str) -> Dict:
        """Extract file system metadata."""
        try:
            stat = os.stat(filepath)
            
            return {
                'filename': os.path.basename(filepath),
                'directory': os.path.dirname(filepath),
                'absolute_path': os.path.abspath(filepath),
                'size_bytes': stat.st_size,
                'size_formatted': format_bytes(stat.st_size),
                'permissions': {
                    'octal': oct(stat.st_mode)[-3:],
                    'readable': os.access(filepath, os.R_OK),
                    'writable': os.access(filepath, os.W_OK),
                    'executable': os.access(filepath, os.X_OK)
                },
                'timestamps': {
                    'access_time': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
                    'modification_time': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'metadata_change_time': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'access_time_unix': stat.st_atime,
                    'modification_time_unix': stat.st_mtime,
                    'metadata_change_time_unix': stat.st_ctime
                },
                'owner': {
                    'uid': stat.st_uid,
                    'gid': stat.st_gid
                },
                'inode': stat.st_ino,
                'device': stat.st_dev,
                'hard_links': stat.st_nlink
            }
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_hashes(self, filepath: str) -> Dict:
        """Calculate multiple hash types for file."""
        hashes = {}
        
        try:
            hashes['md5'] = calculate_hash(filepath, 'md5')
            hashes['sha1'] = calculate_hash(filepath, 'sha1')
            hashes['sha256'] = calculate_hash(filepath, 'sha256')
            
            # Calculate perceptual hash if PIL available
            if PIL_AVAILABLE:
                try:
                    img = Image.open(filepath)
                    # Simple average hash
                    img_small = img.convert('L').resize((8, 8), Image.Resampling.LANCZOS)
                    pixels = list(img_small.getdata())
                    avg = sum(pixels) / len(pixels)
                    bits = ''.join('1' if p > avg else '0' for p in pixels)
                    hashes['average_hash'] = hex(int(bits, 2))[2:].zfill(16)
                    img.close()
                except Exception as e:
                    hashes['average_hash_error'] = str(e)
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def extract_network_metadata(self) -> Dict:
        """Extract network interface metadata (Termux/Android compatible)."""
        network_data = {
            'interfaces': [],
            'routing': [],
            'hostname': None
        }
        
        try:
            # Get hostname
            network_data['hostname'] = os.uname().nodename
        except:
            pass
        
        # Try to read network interfaces from /proc/net/dev
        try:
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
                for line in lines[2:]:  # Skip header lines
                    parts = line.split(':')
                    if len(parts) == 2:
                        iface = parts[0].strip()
                        if iface != 'lo':  # Skip loopback
                            stats = parts[1].split()
                            network_data['interfaces'].append({
                                'name': iface,
                                'rx_bytes': int(stats[0]),
                                'tx_bytes': int(stats[8])
                            })
        except:
            pass
        
        # Try to get MAC address
        try:
            for iface in network_data['interfaces']:
                iface_path = f"/sys/class/net/{iface['name']}/address"
                if os.path.exists(iface_path):
                    with open(iface_path, 'r') as f:
                        iface['mac_address'] = f.read().strip()
        except:
            pass
        
        # Try to read routing table
        try:
            with open('/proc/net/route', 'r') as f:
                lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 8:
                        network_data['routing'].append({
                            'interface': parts[0],
                            'destination': parts[1],
                            'gateway': parts[2],
                            'flags': parts[3]
                        })
        except:
            pass
        
        return network_data


# =============================================================================
# METADATA SPOOFER
# =============================================================================

class MetadataSpoofer:
    """Edit and forge metadata including EXIF and timestamps."""
    
    def __init__(self):
        self.scenarios = {
            'vacation': self._generate_vacation_scenario,
            'business': self._generate_business_scenario,
            'old_photo': self._generate_old_photo_scenario,
            'random': self._generate_random_scenario
        }
    
    def spoof_exif(self, input_path: str, output_path: str, 
                   gps: Optional[str] = None,
                   timestamp: Optional[str] = None,
                   device: Optional[str] = None,
                   software: Optional[str] = None,
                   author: Optional[str] = None,
                   copyright: Optional[str] = None,
                   strip_all: bool = False) -> Dict:
        """Edit EXIF metadata in image."""
        if not PIL_AVAILABLE:
            return {'success': False, 'error': 'PIL not installed'}
        
        try:
            img = Image.open(input_path)
            
            if strip_all:
                # Strip all metadata
                data = list(img.getdata())
                img_clean = Image.new(img.mode, img.size)
                img_clean.putdata(data)
                img_clean.save(output_path, format=img.format)
                return {'success': True, 'action': 'stripped_all_metadata'}
            
            # Use piexif for EXIF manipulation if available
            if PIEXIF_AVAILABLE:
                exif_dict = piexif.load(img.info.get('exif', b''))
                
                # Ensure all dictionaries exist
                if '0th' not in exif_dict:
                    exif_dict['0th'] = {}
                if 'Exif' not in exif_dict:
                    exif_dict['Exif'] = {}
                if 'GPS' not in exif_dict:
                    exif_dict['GPS'] = {}
                
                # Modify GPS
                if gps:
                    try:
                        lat, lon = map(float, gps.split(','))
                        lat_gps, lat_ref = decimal_to_gps(lat)
                        lon_gps, lon_ref = decimal_to_gps(lon)
                        
                        exif_dict['GPS'][piexif.GPSIFD.GPSLatitude] = lat_gps
                        exif_dict['GPS'][piexif.GPSIFD.GPSLatitudeRef] = lat_ref.encode()
                        exif_dict['GPS'][piexif.GPSIFD.GPSLongitude] = lon_gps
                        exif_dict['GPS'][piexif.GPSIFD.GPSLongitudeRef] = lon_ref.encode()
                    except Exception as e:
                        return {'success': False, 'error': f'Invalid GPS format: {e}'}
                
                # Modify timestamp
                if timestamp:
                    try:
                        dt = datetime.datetime.fromisoformat(timestamp)
                        date_str = dt.strftime('%Y:%m:%d')
                        time_str = dt.strftime('%H:%M:%S')
                        datetime_str = f"{date_str} {time_str}"
                        
                        exif_dict['Exif'][piexif.ExifIFD.DateTimeOriginal] = datetime_str.encode()
                        exif_dict['Exif'][piexif.ExifIFD.DateTimeDigitized] = datetime_str.encode()
                        exif_dict['0th'][piexif.ImageIFD.DateTime] = datetime_str.encode()
                    except Exception as e:
                        return {'success': False, 'error': f'Invalid timestamp format: {e}'}
                
                # Modify device info
                if device:
                    exif_dict['0th'][piexif.ImageIFD.Make] = device.split()[0].encode()
                    if len(device.split()) > 1:
                        exif_dict['0th'][piexif.ImageIFD.Model] = ' '.join(device.split()[1:]).encode()
                
                # Modify software
                if software:
                    exif_dict['0th'][piexif.ImageIFD.Software] = software.encode()
                
                # Modify author
                
