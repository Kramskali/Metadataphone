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
                self._save_image(img_clean, output_path, image_format=img.format)
                img_clean.close()
                img.close()
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
                        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                            raise ValueError('latitude must be between -90 and 90 and longitude between -180 and 180')
                        lat_gps, lat_ref = decimal_to_gps(lat)
                        lon_gps, _ = decimal_to_gps(lon)
                        lon_ref = 'E' if lon >= 0 else 'W'
                        
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
                if author:
                    exif_dict['0th'][piexif.ImageIFD.Artist] = author.encode()
                
                # Modify copyright
                if copyright:
                    exif_dict['0th'][piexif.ImageIFD.Copyright] = copyright.encode()

                exif_bytes = piexif.dump(exif_dict)
                self._save_image(img, output_path, image_format=img.format,
                                 exif_bytes=exif_bytes)
                img.close()
                return {
                    'success': True,
                    'output_path': output_path,
                    'modifications': {
                        'gps': bool(gps),
                        'timestamp': bool(timestamp),
                        'device': bool(device),
                        'software': bool(software),
                        'author': bool(author),
                        'copyright': bool(copyright)
                    }
                }

            img.close()
            return {
                'success': False,
                'error': 'piexif is required to edit EXIF metadata; use strip_all to remove metadata'
            }
        except Exception as e:
            try:
                img.close()
            except Exception:
                pass
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _save_image(image: Any, output_path: str, image_format: Optional[str] = None,
                    exif_bytes: Optional[bytes] = None) -> None:
        """Save an image through a temporary file in the destination directory.

        Writing beside the destination makes ``os.replace`` atomic on normal local
        filesystems and prevents a partially encoded image replacing an existing
        output file when Pillow raises an error.
        """
        import tempfile

        destination = Path(output_path).expanduser()
        parent = destination.parent
        if not parent.exists() or not parent.is_dir():
            raise FileNotFoundError(f"Output directory does not exist: {parent}")

        suffix = destination.suffix or '.img'
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f'.{destination.name}.', suffix=suffix, dir=str(parent)
        )
        os.close(descriptor)
        try:
            save_args = {}
            if image_format:
                save_args['format'] = image_format
            if exif_bytes is not None:
                save_args['exif'] = exif_bytes
            image.save(temporary_path, **save_args)
            os.replace(temporary_path, destination)
        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise

    def strip_metadata(self, input_path: str, output_path: str) -> Dict:
        """Create an image copy without embedded metadata."""
        return self.spoof_exif(input_path, output_path, strip_all=True)

    @staticmethod
    def _parse_timestamp(value: str) -> datetime.datetime:
        """Parse the ISO-8601 timestamps accepted by the command-line interface."""
        if not value:
            raise ValueError('timestamp must not be empty')
        return datetime.datetime.fromisoformat(value)

    def modify_timestamps(self, filepath: str, atime: Optional[str] = None,
                          mtime: Optional[str] = None) -> Dict:
        """Update local filesystem access/modification times without shell commands."""
        try:
            existing = os.stat(filepath)
            atime_value = existing.st_atime if atime is None else self._parse_timestamp(atime).timestamp()
            mtime_value = existing.st_mtime if mtime is None else self._parse_timestamp(mtime).timestamp()
            os.utime(filepath, (atime_value, mtime_value))
            return {
                'success': True,
                'filepath': filepath,
                'atime': datetime.datetime.fromtimestamp(atime_value).isoformat(),
                'mtime': datetime.datetime.fromtimestamp(mtime_value).isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _generate_vacation_scenario(self) -> Dict[str, str]:
        return {
            'gps': '48.8566,2.3522',
            'timestamp': '2023-06-15T14:30:00',
            'device': 'Apple iPhone 14 Pro',
            'software': 'Apple iOS'
        }

    def _generate_business_scenario(self) -> Dict[str, str]:
        return {
            'gps': '51.5074,-0.1278',
            'timestamp': '2023-09-18T09:00:00',
            'device': 'Canon EOS R6',
            'software': 'Adobe Lightroom'
        }

    def _generate_old_photo_scenario(self) -> Dict[str, str]:
        return {
            'gps': '40.7128,-74.0060',
            'timestamp': '2005-05-21T12:00:00',
            'device': 'Canon PowerShot A95',
            'software': 'Canon Digital Camera Solution Disk'
        }

    def _generate_random_scenario(self) -> Dict[str, str]:
        """Return a fixed local scenario rather than deriving data from a device."""
        return {
            'gps': '35.6762,139.6503',
            'timestamp': '2022-11-03T16:45:00',
            'device': 'Google Pixel 7',
            'software': 'Google Photos'
        }

    def generate_scenario(self, scenario_name: str, input_path: str,
                          output_path: str) -> Dict:
        """Apply one of the built-in, illustrative metadata scenarios."""
        generator = self.scenarios.get(scenario_name)
        if generator is None:
            return {
                'success': False,
                'error': f"Unknown scenario: {scenario_name}",
                'available_scenarios': sorted(self.scenarios)
            }

        scenario = generator()
        result = self.spoof_exif(input_path, output_path, **scenario)
        result['scenario'] = scenario
        result['scenario_name'] = scenario_name
        return result


# =============================================================================
# METADATA VERIFIER
# =============================================================================

class MetadataVerifier:
    """Perform lightweight, local consistency checks on image metadata.

    Findings identify indicators rather than proving provenance.  The verifier
    never sends the image or its metadata to an external service.
    """

    _EDITING_SOFTWARE = ('photoshop', 'lightroom', 'gimp', 'affinity', 'snapseed')

    def __init__(self, future_tolerance_days: int = 1):
        self.future_tolerance = datetime.timedelta(days=future_tolerance_days)

    @staticmethod
    def _text(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace').rstrip('\x00')
        return str(value).rstrip('\x00')

    @staticmethod
    def _finding(category: str, check: str, result: str, confidence: float,
                 **details: Any) -> ForensicFinding:
        return ForensicFinding(category, check, result, confidence, details)

    @staticmethod
    def _parse_exif_datetime(value: Optional[str]) -> Optional[datetime.datetime]:
        if not value:
            return None
        for pattern in ('%Y:%m:%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
            try:
                return datetime.datetime.strptime(value, pattern)
            except ValueError:
                continue
        return None

    def _read_summary(self, filepath: str) -> Tuple[Dict[str, Any], List[ForensicFinding]]:
        """Read only embedded image data, returning a summary and read findings."""
        findings: List[ForensicFinding] = []
        summary: Dict[str, Any] = {'source_file': filepath, 'exif_present': False}
        if not PIL_AVAILABLE:
            findings.append(self._finding(
                'Environment', 'Image Reader', 'SUSPICIOUS', 0.0,
                reason='Pillow is not installed; embedded metadata was not inspected'
            ))
            return summary, findings

        try:
            with Image.open(filepath) as image:
                summary.update({
                    'format': image.format,
                    'mode': image.mode,
                    'dimensions': {'width': image.width, 'height': image.height}
                })
                raw_exif = image.info.get('exif', b'')
                summary['exif_present'] = bool(raw_exif)
                findings.append(self._finding(
                    'File', 'Image Readability', 'REAL', 0.95,
                    format=image.format, width=image.width, height=image.height
                ))

                if not raw_exif:
                    findings.append(self._finding(
                        'Metadata', 'EXIF Presence', 'REAL', 0.5,
                        note='No EXIF block is present; this is common after export or sharing'
                    ))
                    return summary, findings

                if not PIEXIF_AVAILABLE:
                    findings.append(self._finding(
                        'Environment', 'EXIF Detail Reader', 'SUSPICIOUS', 0.0,
                        reason='piexif is not installed; detailed checks were skipped'
                    ))
                    return summary, findings

                exif_data = piexif.load(raw_exif)
                zeroth = exif_data.get('0th', {})
                exif = exif_data.get('Exif', {})
                gps = exif_data.get('GPS', {})
                summary.update({
                    'make': self._text(zeroth.get(piexif.ImageIFD.Make)),
                    'model': self._text(zeroth.get(piexif.ImageIFD.Model)),
                    'software': self._text(zeroth.get(piexif.ImageIFD.Software)),
                    'datetime': self._text(zeroth.get(piexif.ImageIFD.DateTime)),
                    'datetime_original': self._text(exif.get(piexif.ExifIFD.DateTimeOriginal)),
                    'datetime_digitized': self._text(exif.get(piexif.ExifIFD.DateTimeDigitized)),
                    'gps_present': bool(gps)
                })
                if gps:
                    lat = gps.get(piexif.GPSIFD.GPSLatitude)
                    lon = gps.get(piexif.GPSIFD.GPSLongitude)
                    lat_ref = self._text(gps.get(piexif.GPSIFD.GPSLatitudeRef))
                    lon_ref = self._text(gps.get(piexif.GPSIFD.GPSLongitudeRef))
                    try:
                        summary['gps'] = {
                            'latitude': gps_to_decimal(lat, lat_ref),
                            'longitude': gps_to_decimal(lon, lon_ref)
                        }
                    except (TypeError, ValueError, ZeroDivisionError):
                        summary['gps'] = None
        except Exception as e:
            findings.append(self._finding(
                'File', 'Image Readability', 'FAKE', 0.95, error=str(e)
            ))
        return summary, findings

    def verify(self, filepath: str) -> VerificationReport:
        """Return local metadata consistency findings for ``filepath``."""
        if not os.path.isfile(filepath):
            finding = self._finding('File', 'File Exists', 'FAKE', 1.0, path=filepath)
            return VerificationReport(
                VerificationResult.FAKE, 1.0, [finding], {'source_file': filepath}
            )

        summary, findings = self._read_summary(filepath)
        now = datetime.datetime.now()
        date_fields = (
            ('DateTime', summary.get('datetime')),
            ('DateTimeOriginal', summary.get('datetime_original')),
            ('DateTimeDigitized', summary.get('datetime_digitized'))
        )
        valid_dates: List[Tuple[str, datetime.datetime]] = []
        for field_name, raw_value in date_fields:
            if not raw_value:
                continue
            parsed = self._parse_exif_datetime(raw_value)
            if parsed is None:
                findings.append(self._finding(
                    'Temporal', 'Date Format', 'SUSPICIOUS', 0.55,
                    field=field_name, value=raw_value
                ))
                continue
            valid_dates.append((field_name, parsed))
            if parsed > now + self.future_tolerance:
                findings.append(self._finding(
                    'Temporal', 'Future Date', 'FAKE', 0.98,
                    field=field_name, value=raw_value, current_time=now.isoformat()
                ))

        if len({value for _, value in valid_dates}) > 1:
            findings.append(self._finding(
                'Temporal', 'Timestamp Consistency', 'SUSPICIOUS', 0.65,
                dates={field: value.isoformat() for field, value in valid_dates}
            ))

        software = (summary.get('software') or '').lower()
        if any(marker in software for marker in self._EDITING_SOFTWARE):
            findings.append(self._finding(
                'Software', 'Editing Software', 'SUSPICIOUS', 0.6,
                software=summary.get('software'),
                note='Editing software is not evidence of fabrication by itself'
            ))

        gps = summary.get('gps')
        if summary.get('gps_present'):
            if not gps or gps.get('latitude') is None or gps.get('longitude') is None:
                findings.append(self._finding(
                    'Location', 'GPS Coordinates', 'SUSPICIOUS', 0.65,
                    reason='GPS EXIF is incomplete or could not be decoded'
                ))
            elif not (-90 <= gps['latitude'] <= 90 and -180 <= gps['longitude'] <= 180):
                findings.append(self._finding(
                    'Location', 'GPS Coordinates', 'FAKE', 0.9, coordinates=gps
                ))

        if any(finding.result == 'FAKE' for finding in findings):
            overall_result = VerificationResult.FAKE
            confidence = max(finding.confidence for finding in findings if finding.result == 'FAKE')
        elif any(finding.result == 'SUSPICIOUS' for finding in findings):
            overall_result = VerificationResult.SUSPICIOUS
            confidence = max(finding.confidence for finding in findings if finding.result == 'SUSPICIOUS')
        else:
            overall_result = VerificationResult.REAL
            confidence = 0.8

        return VerificationReport(overall_result, confidence, findings, summary)


# =============================================================================
# PHONE METADATA (OFFLINE / EXPLICIT INPUT ONLY)
# =============================================================================

class PhoneMetadata:
    """Analyze explicitly supplied cell logs without interrogating a device.

    Automatic cell and Wi-Fi collection normally requires platform tools and may
    expose sensitive data.  These methods deliberately return a clearly marked
    limited result in environments where no caller-supplied data is available.
    """

    def get_cell_info(self) -> Dict:
        return {
            'cell_towers': [],
            'available': False,
            'source': 'not_collected',
            'reason': 'Automatic cell-tower collection is disabled; provide an explicit local log for analysis.'
        }

    def get_wifi_info(self) -> Dict:
        return {
            'networks': [],
            'available': False,
            'source': 'not_collected',
            'reason': 'Automatic Wi-Fi collection is disabled to avoid collecting nearby network data.'
        }

    @staticmethod
    def parse_cell_log(log_line: str) -> Optional[Dict]:
        """Parse ``timestamp,cell_id,lac,mcc,mnc,lat,lon,signal`` safely.

        Blank lines, comments, headers, and malformed values return ``None`` so a
        batch caller can skip them without exposing or executing their contents.
        """
        if not isinstance(log_line, str):
            return None
        line = log_line.strip()
        if not line or line.startswith('#'):
            return None
        parts = [part.strip() for part in line.split(',')]
        if len(parts) != 8:
            return None
        try:
            timestamp = float(parts[0])
            result = {
                'timestamp': int(timestamp) if timestamp.is_integer() else timestamp,
                'cell_id': parts[1],
                'location_area_code': parts[2],
                'mcc': parts[3],
                'mnc': parts[4],
                'gps': {'lat': float(parts[5]), 'lon': float(parts[6])},
                'signal_dbm': float(parts[7])
            }
        except (TypeError, ValueError):
            return None
        if not result['cell_id'] or not (-90 <= result['gps']['lat'] <= 90):
            return None
        if not (-180 <= result['gps']['lon'] <= 180):
            return None
        return result

    @staticmethod
    def _coordinates(record: Dict) -> Optional[Tuple[float, float]]:
        try:
            gps = record.get('gps', {})
            latitude = float(gps.get('lat'))
            longitude = float(gps.get('lon'))
            if -90 <= latitude <= 90 and -180 <= longitude <= 180:
                return latitude, longitude
        except (AttributeError, TypeError, ValueError):
            pass
        return None

    @staticmethod
    def _haversine_km(first: Tuple[float, float], second: Tuple[float, float]) -> float:
        latitude_1, longitude_1 = map(math.radians, first)
        latitude_2, longitude_2 = map(math.radians, second)
        latitude_delta = latitude_2 - latitude_1
        longitude_delta = longitude_2 - longitude_1
        a_value = (math.sin(latitude_delta / 2) ** 2 +
                   math.cos(latitude_1) * math.cos(latitude_2) *
                   math.sin(longitude_delta / 2) ** 2)
        return 6371.0088 * 2 * math.atan2(math.sqrt(a_value), math.sqrt(1 - a_value))

    def analyze_movement(self, logs: List[Dict], max_speed_kmh: float = 1000.0) -> Dict:
        """Flag impossible speeds between chronological, caller-supplied positions."""
        suspicious_patterns: List[Dict] = []
        segments: List[Dict] = []
        valid_records: List[Dict] = []
        for record in logs or []:
            if not isinstance(record, dict) or self._coordinates(record) is None:
                continue
            try:
                float(record['timestamp'])
            except (KeyError, TypeError, ValueError):
                continue
            valid_records.append(record)
        valid_records.sort(key=lambda record: float(record['timestamp']))

        for previous, current in zip(valid_records, valid_records[1:]):
            time_delta = float(current['timestamp']) - float(previous['timestamp'])
            if time_delta <= 0:
                suspicious_patterns.append({
                    'type': 'invalid_timestamp_order',
                    'previous_timestamp': previous['timestamp'],
                    'timestamp': current['timestamp']
                })
                continue
            distance = self._haversine_km(self._coordinates(previous), self._coordinates(current))
            speed = distance / time_delta * 3600
            segment = {
                'start_timestamp': previous['timestamp'],
                'end_timestamp': current['timestamp'],
                'distance_km': round(distance, 3),
                'duration_seconds': time_delta,
                'speed_kmh': round(speed, 3)
            }
            segments.append(segment)
            if speed > max_speed_kmh:
                suspicious_patterns.append({
                    'type': 'impossible_speed',
                    **segment,
                    'threshold_kmh': max_speed_kmh,
                    'from_cell_id': previous.get('cell_id'),
                    'to_cell_id': current.get('cell_id')
                })

        return {
            'records_provided': len(logs or []),
            'valid_records': len(valid_records),
            'movement_segments': segments,
            'suspicious_patterns': suspicious_patterns,
            'max_speed_kmh': max_speed_kmh
        }


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the command parser for collection, spoofing, verification, and logs."""
    parser = argparse.ArgumentParser(description='Metadata Forensics Suite for Termux')
    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')

    collect_parser = subparsers.add_parser('collect', help='extract image and filesystem metadata')
    collect_parser.add_argument('-i', '--input', required=True, help='input file path')
    collect_parser.add_argument('--no-network', action='store_true',
                                help='do not include local network interface metadata')
    collect_parser.add_argument('--compact', action='store_true', help='emit compact JSON')

    spoof_parser = subparsers.add_parser('spoof', help='edit or remove image metadata')
    spoof_parser.add_argument('-i', '--input', required=True, help='input image path')
    spoof_parser.add_argument('-o', '--output', required=True, help='output image path')
    spoof_parser.add_argument('--gps', help='latitude,longitude in decimal degrees')
    spoof_parser.add_argument('--timestamp', help='ISO-8601 timestamp')
    spoof_parser.add_argument('--device', help='camera make and model')
    spoof_parser.add_argument('--software', help='software EXIF value')
    spoof_parser.add_argument('--author', help='artist EXIF value')
    spoof_parser.add_argument('--copyright', help='copyright EXIF value')
    spoof_parser.add_argument('--strip-all', action='store_true', help='remove embedded metadata')
    spoof_parser.add_argument('--scenario', choices=('vacation', 'business', 'old_photo', 'random'),
                             help='apply a built-in example scenario')
    spoof_parser.add_argument('--atime', help='set output filesystem access time (ISO-8601)')
    spoof_parser.add_argument('--mtime', help='set output filesystem modification time (ISO-8601)')
    spoof_parser.add_argument('--compact', action='store_true', help='emit compact JSON')

    verify_parser = subparsers.add_parser('verify', help='check metadata consistency')
    verify_parser.add_argument('-i', '--input', required=True, help='input image path')
    verify_parser.add_argument('--compact', action='store_true', help='emit compact JSON')

    phone_parser = subparsers.add_parser('phone', help='analyze explicitly supplied phone metadata logs')
    phone_parser.add_argument('--cell-info', action='store_true',
                              help='show the limited cell-information result')
    phone_parser.add_argument('--wifi-info', action='store_true',
                              help='show the limited Wi-Fi-information result')
    phone_parser.add_argument('--log-file', help='local CSV cell log to analyze explicitly')
    phone_parser.add_argument('--compact', action='store_true', help='emit compact JSON')

    return parser


def _report_to_dict(report: VerificationReport) -> Dict:
    return {
        'overall_result': report.overall_result.value,
        'confidence_score': report.confidence_score,
        'findings': [asdict(finding) for finding in report.findings],
        'metadata_summary': report.metadata_summary
    }


def main(argv: Optional[List[str]] = None) -> int:
    """Dispatch the documented CLI commands and print one JSON result."""
    parser = create_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    if args.command == 'collect':
        result = MetadataCollector().collect_all(args.input, include_network=not args.no_network)
    elif args.command == 'spoof':
        spoofer = MetadataSpoofer()
        if args.scenario:
            result = spoofer.generate_scenario(args.scenario, args.input, args.output)
        else:
            result = spoofer.spoof_exif(
                args.input, args.output, gps=args.gps, timestamp=args.timestamp,
                device=args.device, software=args.software, author=args.author,
                copyright=args.copyright, strip_all=args.strip_all
            )
        if result.get('success') and (args.atime or args.mtime):
            result['filesystem_timestamps'] = spoofer.modify_timestamps(
                args.output, atime=args.atime, mtime=args.mtime
            )
            if not result['filesystem_timestamps']['success']:
                result['success'] = False
    elif args.command == 'verify':
        result = _report_to_dict(MetadataVerifier().verify(args.input))
    elif args.command == 'phone':
        phone = PhoneMetadata()
        result = {}
        if args.cell_info or not (args.cell_info or args.wifi_info or args.log_file):
            result['cell_info'] = phone.get_cell_info()
        if args.wifi_info:
            result['wifi_info'] = phone.get_wifi_info()
        if args.log_file:
            try:
                with open(args.log_file, 'r', encoding='utf-8') as log_file:
                    logs = [entry for line in log_file if (entry := phone.parse_cell_log(line))]
                result['movement_analysis'] = phone.analyze_movement(logs)
            except OSError as e:
                result['movement_analysis'] = {'error': str(e), 'suspicious_patterns': []}
    else:
        parser.error(f'Unsupported command: {args.command}')
        return 2

    print_json(result, pretty=not getattr(args, 'compact', False))
    return 1 if isinstance(result, dict) and result.get('success') is False else 0


if __name__ == '__main__':
    sys.exit(main())
