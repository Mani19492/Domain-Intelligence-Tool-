import os
import json
import pickle
import requests
import socket
import ssl
import subprocess
import whois
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
import dns.resolver
import nmap
import threading
import time
import hashlib
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import base64
from PIL import Image as PILImage
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import re
from urllib.parse import urljoin

app = Flask(__name__)

# DNSDumpster API configuration
DNSDUMPSTER_API_KEY = "e33c4c55e9caa8b2a0d64421ae1417fa40c05c118710286eb766d1c1e05d0a16"
DNSDUMPSTER_BASE_URL = "https://dnsdumpster.com"

# VirusTotal API configuration (you'll need to get your own API key)
VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2"

# SecurityHeaders.com API
SECURITYHEADERS_BASE_URL = "https://securityheaders.com"

# Cache file for reverse IP lookups
CACHE_FILE = 'reverse_ip_cache.pkl'

def load_cache():
    """Load cached reverse IP lookup results"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                return pickle.load(f)
        except:
            return {}
    return {}

def save_cache(cache):
    """Save reverse IP lookup results to cache"""
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(cache, f)
    except:
        pass

def get_ip_geolocation(ip):
    """Get geolocation data for an IP address"""
    try:
        # Using ipapi.co for geolocation (free tier)
        response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'country': data.get('country_name', 'Unknown'),
                'country_code': data.get('country_code', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': data.get('latitude', 0),
                'longitude': data.get('longitude', 0),
                'org': data.get('org', 'Unknown'),
                'asn': data.get('asn', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown')
            }
    except Exception as e:
        print(f"Error getting geolocation for {ip}: {e}")
    
    return {
        'ip': ip,
        'country': 'Unknown',
        'country_code': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'org': 'Unknown',
        'asn': 'Unknown',
        'timezone': 'Unknown'
    }

def get_virustotal_data(domain):
    """Get VirusTotal analysis data for domain"""
    try:
        if VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
            return {'error': 'VirusTotal API key not configured'}
            
        url = f"{VIRUSTOTAL_BASE_URL}/domain/report"
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'domain': domain
        }
        
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                'response_code': data.get('response_code', 0),
                'positives': data.get('positives', 0),
                'total': data.get('total', 0),
                'scan_date': data.get('scan_date', 'Unknown'),
                'scans': data.get('scans', {}),
                'detected_urls': data.get('detected_urls', [])
            }
    except Exception as e:
        print(f"Error getting VirusTotal data: {e}")
    
    return {'error': 'VirusTotal data unavailable'}

def get_security_headers_analysis(domain):
    """Get security headers analysis from SecurityHeaders.com"""
    try:
        url = f"{SECURITYHEADERS_BASE_URL}/?q={domain}&followRedirects=on"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Parse the response for security headers grade
            content = response.text
            
            # Extract grade (simplified parsing)
            grade_match = re.search(r'class="grade-([A-F])"', content)
            grade = grade_match.group(1) if grade_match else 'Unknown'
            
            return {
                'grade': grade,
                'url': url,
                'analysis_available': True
            }
    except Exception as e:
        print(f"Error getting security headers analysis: {e}")
    
    return {'error': 'Security headers analysis unavailable'}

def get_wayback_machine_data(domain):
    """Get Wayback Machine snapshots for domain"""
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=10"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # First row is headers
                snapshots = []
                for row in data[1:]:  # Skip header row
                    snapshots.append({
                        'timestamp': row[1],
                        'url': row[2],
                        'status': row[4],
                        'archived_url': f"http://web.archive.org/web/{row[1]}/{row[2]}"
                    })
                return snapshots
    except Exception as e:
        print(f"Error getting Wayback Machine data: {e}")
    
    return []

def get_threat_intelligence(domain):
    """Get threat intelligence data from multiple sources"""
    threats = []
    
    try:
        # Check against known malicious domain lists (simplified)
        malicious_indicators = [
            'suspicious', 'malware', 'phishing', 'spam', 'botnet'
        ]
        
        # This is a simplified example - in production you'd use real threat intel APIs
        for indicator in malicious_indicators:
            if indicator in domain.lower():
                threats.append(f"Domain contains suspicious keyword: {indicator}")
        
        # Add more threat intelligence sources here
        
    except Exception as e:
        print(f"Error getting threat intelligence: {e}")
    
    return threats if threats else ['No threats detected']

def query_dnsdumpster(domain):
    """Query DNSDumpster API for domain information"""
    try:
        # DNSDumpster web scraping approach
        session = requests.Session()
        url = f"{DNSDUMPSTER_BASE_URL}/"
        
        # Get CSRF token
        response = session.get(url, timeout=10)
        csrf_token = re.findall(r'name="csrfmiddlewaretoken" value="([^"]*)"', response.text)
        
        if csrf_token:
            # Submit domain for analysis
            data = {
                'csrfmiddlewaretoken': csrf_token[0],
                'targetip': domain,
                'user': 'free'
            }
            
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = session.post(url, data=data, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Parse the response for subdomain information
                subdomains = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')', response.text)
                unique_subdomains = list(set(subdomains))
                
                # Parse DNS records
                dns_records = []
                dns_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                dns_matches = re.findall(dns_pattern, response.text)
                
                for ip, subdomain in dns_matches:
                    dns_records.append({
                        'ip': ip,
                        'subdomain': subdomain,
                        'type': 'A'
                    })
                
                return {
                    'subdomains': unique_subdomains,
                    'dns_records': dns_records,
                    'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set'),
                    'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set'),
                    'Cross-Origin-Embedder-Policy': headers.get('Cross-Origin-Embedder-Policy', 'Not Set')
                }
        else:
            print("Could not get CSRF token from DNSDumpster")
            return None
            
    except Exception as e:
        print(f"Error querying DNSDumpster: {e}")
        return None

def get_domain_info(domain):
    """Get comprehensive domain information"""
    info = {
        'domain': domain,
        'ip_addresses': [],
        'dns_records': {},
        'subdomains': [],
        'whois_info': {},
        'ssl_info': {},
        'open_ports': [],
        'technologies': [],
        'security_headers': {},
        'geolocation': [],
        'network_map': {},
        'dnsdumpster_data': {},
        'virustotal_data': {},
        'wayback_data': [],
        'threat_intelligence': [],
        'security_analysis': {}
    }
    
    try:
        # Get VirusTotal data
        info['virustotal_data'] = get_virustotal_data(domain)
        
        # Get Wayback Machine data
        info['wayback_data'] = get_wayback_machine_data(domain)
        
        # Get threat intelligence
        info['threat_intelligence'] = get_threat_intelligence(domain)
        
        # Get security headers analysis
        info['security_analysis'] = get_security_headers_analysis(domain)
        
        # Query DNSDumpster for additional data
        dnsdumpster_result = query_dnsdumpster(domain)
        if dnsdumpster_result:
            info['dnsdumpster_data'] = dnsdumpster_result
            
            # Extract subdomains from DNSDumpster
            if 'subdomains' in dnsdumpster_result:
                for subdomain in dnsdumpster_result['subdomains']:
                    if subdomain not in info['subdomains']:
                        info['subdomains'].append(subdomain)
            
            # Extract DNS records from DNSDumpster
            if 'dns_records' in dnsdumpster_result:
                info['dnsdumpster_dns'] = dnsdumpster_result['dns_records']
        
        # Get IP addresses
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            info['ip_addresses'] = list(set(ip_addresses))
        except:
            try:
                ip = socket.gethostbyname(domain)
                info['ip_addresses'] = [ip]
            except:
                pass
        
        # Get geolocation for each IP
        for ip in info['ip_addresses']:
            geo_data = get_ip_geolocation(ip)
            info['geolocation'].append(geo_data)
        
        # DNS Records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                info['dns_records'][record_type] = [str(rdata) for rdata in answers]
            except:
                info['dns_records'][record_type] = []
        
        # WHOIS Information
        try:
            w = whois.whois(domain)
            info['whois_info'] = {
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else 'Unknown'
            }
        except:
            info['whois_info'] = {'error': 'WHOIS lookup failed'}
        
        # SSL Certificate Information
        if info['ip_addresses']:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        info['ssl_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'serial_number': cert['serialNumber'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
                        }
            except:
                info['ssl_info'] = {'error': 'SSL certificate not available'}
        
        # Port Scanning
        if info['ip_addresses']:
            try:
                nm = nmap.PortScanner()
                for ip in info['ip_addresses'][:1]:  # Scan only first IP to avoid timeout
                    result = nm.scan(ip, '21-443,993,995,8080,8443', timeout=30)
                    if ip in result['scan']:
                        for port in result['scan'][ip]['tcp']:
                            if result['scan'][ip]['tcp'][port]['state'] == 'open':
                                info['open_ports'].append({
                                    'ip': ip,
                                    'port': port,
                                    'service': result['scan'][ip]['tcp'][port].get('name', 'unknown'),
                                    'version': result['scan'][ip]['tcp'][port].get('version', '')
                                })
            except:
                info['open_ports'] = [{'error': 'Port scan failed'}]
        
        # Security Headers Check
        try:
            response = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set')
            }
            info['security_headers'] = security_headers
        except:
            info['security_headers'] = {'error': 'Could not fetch security headers'}
        
        # Technology Detection (basic)
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            content = response.text.lower()
            headers = response.headers
            
            technologies = []
            
            # Server detection
            server = headers.get('Server', '')
            if server:
                technologies.append(f"Server: {server}")
            
            # Framework detection
            if 'wordpress' in content:
                technologies.append('WordPress')
            if 'drupal' in content:
                technologies.append('Drupal')
            if 'joomla' in content:
                technologies.append('Joomla')
            if 'react' in content:
                technologies.append('React')
            if 'angular' in content:
                technologies.append('Angular')
            if 'vue' in content:
                technologies.append('Vue.js')
            if 'bootstrap' in content:
                technologies.append('Bootstrap')
            if 'jquery' in content:
                technologies.append('jQuery')
            
            info['technologies'] = technologies
        except:
            info['technologies'] = ['Detection failed']
        
        # Create network map data
        info['network_map'] = create_network_map_data(info)
        
    except Exception as e:
        print(f"Error in get_domain_info: {e}")
    
    return info

def create_network_map_data(info):
    """Create network map visualization data"""
    nodes = []
    edges = []
    
    # Main domain node
    nodes.append({
        'id': info['domain'],
        'label': info['domain'],
        'type': 'domain',
        'color': '#4CAF50'
    })
    
    # IP address nodes
    for i, ip in enumerate(info['ip_addresses']):
        nodes.append({
            'id': f"ip_{i}",
            'label': ip,
            'type': 'ip',
            'color': '#2196F3'
        })
        edges.append({
            'from': info['domain'],
            'to': f"ip_{i}",
            'label': 'resolves to'
        })
    
    # DNS server nodes
    if 'NS' in info['dns_records']:
        for i, ns in enumerate(info['dns_records']['NS']):
            nodes.append({
                'id': f"ns_{i}",
                'label': ns,
                'type': 'nameserver',
                'color': '#FF9800'
            })
            edges.append({
                'from': info['domain'],
                'to': f"ns_{i}",
                'label': 'NS'
            })
    
    # MX server nodes
    if 'MX' in info['dns_records']:
        for i, mx in enumerate(info['dns_records']['MX']):
            nodes.append({
                'id': f"mx_{i}",
                'label': mx,
                'type': 'mailserver',
                'color': '#9C27B0'
            })
            edges.append({
                'from': info['domain'],
                'to': f"mx_{i}",
                'label': 'MX'
            })
    
    return {'nodes': nodes, 'edges': edges}

def generate_pdf_report(domain_info):
    """Generate PDF report of domain analysis"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue
    )
    
    # Title
    story.append(Paragraph(f"Domain Intelligence Report: {domain_info['domain']}", title_style))
    story.append(Spacer(1, 20))
    
    # Generation date
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    summary_text = f"""
    This report provides a comprehensive analysis of the domain {domain_info['domain']}. 
    The analysis includes WHOIS information, DNS records, SSL certificates, security headers, 
    geolocation data, and threat intelligence assessment.
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 12))
    
    # IP Addresses
    story.append(Paragraph("IP Addresses", heading_style))
    if domain_info['ip_addresses']:
        ip_data = [[ip] for ip in domain_info['ip_addresses']]
        ip_table = Table(ip_data)
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(ip_table)
    story.append(Spacer(1, 12))
    
    # VirusTotal Analysis
    story.append(Paragraph("VirusTotal Analysis", heading_style))
    if 'error' not in domain_info['virustotal_data']:
        vt_data = [
            ['Positives', str(domain_info['virustotal_data'].get('positives', 0))],
            ['Total Scans', str(domain_info['virustotal_data'].get('total', 0))],
            ['Scan Date', str(domain_info['virustotal_data'].get('scan_date', 'Unknown'))]
        ]
        vt_table = Table(vt_data)
        vt_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(vt_table)
    else:
        story.append(Paragraph("VirusTotal data not available", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Threat Intelligence
    story.append(Paragraph("Threat Intelligence", heading_style))
    if domain_info['threat_intelligence']:
        for threat in domain_info['threat_intelligence']:
            story.append(Paragraph(f"• {threat}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Geolocation Information
    story.append(Paragraph("Geolocation Information", heading_style))
    if domain_info['geolocation']:
        geo_data = [['IP', 'Country', 'Region', 'City', 'Organization', 'ASN']]
        for geo in domain_info['geolocation']:
            geo_data.append([
                geo['ip'],
                geo['country'],
                geo['region'],
                geo['city'],
                geo['org'],
                geo['asn']
            ])
        
        geo_table = Table(geo_data)
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(geo_table)
    story.append(Spacer(1, 12))
    
    # Subdomains
    story.append(Paragraph("Discovered Subdomains", heading_style))
    if domain_info['subdomains']:
        subdomain_text = ', '.join(domain_info['subdomains'][:20])  # Limit to first 20
        if len(domain_info['subdomains']) > 20:
            subdomain_text += f" ... and {len(domain_info['subdomains']) - 20} more"
        story.append(Paragraph(subdomain_text, styles['Normal']))
    else:
        story.append(Paragraph("No subdomains discovered", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # DNS Records
    story.append(Paragraph("DNS Records", heading_style))
    dns_data = [['Record Type', 'Values']]
    for record_type, values in domain_info['dns_records'].items():
        if values:
            dns_data.append([record_type, ', '.join(values[:3])])  # Limit to first 3 values
    
    dns_table = Table(dns_data)
    dns_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(dns_table)
    story.append(Spacer(1, 12))
    
    # WHOIS Information
    story.append(Paragraph("WHOIS Information", heading_style))
    whois_data = []
    for key, value in domain_info['whois_info'].items():
        if key != 'error':
            whois_data.append([key.replace('_', ' ').title(), str(value)])
    
    if whois_data:
        whois_table = Table(whois_data)
        whois_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(whois_table)
    story.append(Spacer(1, 12))
    
    # Open Ports
    story.append(Paragraph("Open Ports", heading_style))
    if domain_info['open_ports'] and not any('error' in port for port in domain_info['open_ports']):
        port_data = [['IP', 'Port', 'Service', 'Version']]
        for port_info in domain_info['open_ports']:
            port_data.append([
                port_info.get('ip', ''),
                str(port_info.get('port', '')),
                port_info.get('service', ''),
                port_info.get('version', '')
            ])
        
        port_table = Table(port_data)
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("No open ports detected or scan failed", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Security Headers
    story.append(Paragraph("Security Headers", heading_style))
    if 'error' not in domain_info['security_headers']:
        security_data = []
        for header, value in domain_info['security_headers'].items():
            security_data.append([header, value])
        
        security_table = Table(security_data)
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(security_table)
    story.append(Spacer(1, 12))
    
    # Technologies
    story.append(Paragraph("Detected Technologies", heading_style))
    if domain_info['technologies']:
        tech_text = ', '.join(domain_info['technologies'])
        story.append(Paragraph(tech_text, styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Security Analysis Summary
    story.append(Paragraph("Security Analysis Summary", heading_style))
    if 'error' not in domain_info['security_analysis']:
        story.append(Paragraph(f"Security Headers Grade: {domain_info['security_analysis'].get('grade', 'Unknown')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('id')
        password = request.form.get('password')
        
        # Simple authentication (in production, use proper authentication)
        if user_id == 'admin' and password == 'password123':
            return render_template('index.html')
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/analyze', methods=['POST'])
def analyze_domain():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Get domain information
        domain_info = get_domain_info(domain)
        
        return jsonify(domain_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_report/<domain>')
def download_report(domain):
    try:
        # Get domain information
        domain_info = get_domain_info(domain)
        
        # Generate PDF
        pdf_buffer = generate_pdf_report(domain_info)
        
        # Create filename
        filename = f"domain_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)