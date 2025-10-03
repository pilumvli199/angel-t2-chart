import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-GUI backend
import matplotlib.pyplot as plt
from io import BytesIO

# ---- SmartAPI import ----
SmartConnect = None
try:
    from SmartApi import SmartConnect as _SC
    SmartConnect = _SC
    logging.info("SmartConnect imported successfully!")
except Exception as e:
    logging.error(f"Failed to import SmartConnect: {e}")
    SmartConnect = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('angel-bot')

# Load config from env
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# Price history storage (last 1 hour)
price_history = {}

def tele_send_http(chat_id: str, text: str, photo_path=None):
    """Send message with optional photo using Telegram Bot HTTP API"""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set')
            return False
        
        if photo_path:
            # Send photo with caption
            url = f"https://api.telegram.org/bot{token}/sendPhoto"
            with open(photo_path, 'rb') as photo:
                files = {'photo': photo}
                data = {
                    'chat_id': chat_id,
                    'caption': text,
                    'parse_mode': 'HTML'
                }
                r = requests.post(url, data=data, files=files, timeout=30)
        else:
            # Send text only
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML"
            }
            r = requests.post(url, json=payload, timeout=10)
        
        if r.status_code != 200:
            logger.warning(f'Telegram API returned {r.status_code}: {r.text}')
            return False
        return True
    except Exception as e:
        logger.exception(f'Failed to send Telegram message: {e}')
        return False

def login_and_setup(api_key, client_id, password, totp_secret):
    if SmartConnect is None:
        raise RuntimeError('SmartAPI SDK not available')
    smartApi = SmartConnect(api_key=api_key)
    totp = pyotp.TOTP(totp_secret).now()
    logger.info('Logging in to SmartAPI...')
    data = smartApi.generateSession(client_id, password, totp)
    if not data or data.get('status') is False:
        raise RuntimeError(f"Login failed: {data}")
    authToken = data['data']['jwtToken']
    refreshToken = data['data']['refreshToken']
    try:
        feedToken = smartApi.getfeedToken()
    except Exception:
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        pass
    return smartApi, authToken, refreshToken, feedToken

def get_market_data_angel(smartApi):
    """Get live data for indices and stocks"""
    try:
        symbols = {
            'NIFTY 50': '99926000',
            'NIFTY BANK': '99926009',
            'TCS': '11536',
            'HDFCBANK': '1333',
            'SBIN': '3045',
            'RELIANCE': '2885'
        }
        
        result = {}
        
        # Try SDK method first
        if hasattr(smartApi, 'getMarketData'):
            try:
                all_tokens = list(symbols.values())
                data = smartApi.getMarketData('LTP', {'NSE': all_tokens})
                
                if data and data.get('status'):
                    fetched = data.get('data', {}).get('fetched', [])
                    for item in fetched:
                        token = item.get('symbolToken', '')
                        ltp = item.get('ltp', 0)
                        for name, tok in symbols.items():
                            if tok == token:
                                result[name] = float(ltp) if ltp else 0
                                break
                
                if result:
                    return result
            except Exception as e:
                logger.warning(f"getMarketData failed: {e}")
        
        # Fallback to direct API
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        payload = {
            "mode": "LTP",
            "exchangeTokens": {
                "NSE": list(symbols.values())
            }
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                fetched = data.get('data', {}).get('fetched', [])
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = item.get('ltp', 0)
                    for name, tok in symbols.items():
                        if tok == token:
                            result[name] = float(ltp) if ltp else 0
                            break
        
        return result if result else None
        
    except Exception as e:
        logger.exception(f"Failed to fetch market data: {e}")
        return None

def store_price_history(prices):
    """Store prices with timestamp (keep last 1 hour)"""
    global price_history
    
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(hours=1)
    
    # Add current prices
    for symbol, price in prices.items():
        if symbol not in price_history:
            price_history[symbol] = []
        
        price_history[symbol].append({
            'time': current_time,
            'price': price
        })
        
        # Remove old data (older than 1 hour)
        price_history[symbol] = [
            p for p in price_history[symbol] 
            if p['time'] > cutoff_time
        ]

def calculate_alerts(symbol, current_price):
    """Calculate price changes and generate alerts"""
    if symbol not in price_history or len(price_history[symbol]) < 2:
        return None
    
    history = price_history[symbol]
    oldest = history[0]['price']
    
    # Calculate change
    change = current_price - oldest
    change_pct = (change / oldest) * 100 if oldest else 0
    
    # Alert conditions
    alert = None
    if abs(change_pct) >= 2.0:
        alert = "🔥 BIG MOVE"
    elif abs(change_pct) >= 1.0:
        alert = "⚡ ALERT"
    
    return {
        'change': change,
        'change_pct': change_pct,
        'alert': alert,
        'start_price': oldest,
        'high': max(p['price'] for p in history),
        'low': min(p['price'] for p in history)
    }

def create_chart(symbol):
    """Create price chart for last 1 hour"""
    if symbol not in price_history or len(price_history[symbol]) < 2:
        return None
    
    try:
        history = price_history[symbol]
        df = pd.DataFrame(history)
        
        plt.figure(figsize=(10, 6))
        plt.style.use('dark_background')
        
        # Plot line
        plt.plot(df['time'], df['price'], color='#00ff00', linewidth=2, marker='o', markersize=4)
        
        # Fill area
        plt.fill_between(df['time'], df['price'], alpha=0.3, color='#00ff00')
        
        # Styling
        plt.title(f'{symbol} - Last 1 Hour', fontsize=16, fontweight='bold')
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Price (₹)', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Save to bytes
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight', facecolor='#1a1a1a')
        buf.seek(0)
        
        # Save to file
        filename = f'/tmp/chart_{symbol.replace(" ", "_")}.png'
        with open(filename, 'wb') as f:
            f.write(buf.getvalue())
        
        plt.close()
        return filename
        
    except Exception as e:
        logger.exception(f"Failed to create chart: {e}")
        return None

def format_alert_message(prices):
    """Format comprehensive alert message"""
    messages = []
    messages.append("📊 <b>MARKET UPDATE</b>\n")
    
    # Indices
    messages.append("🔵 <b>INDICES</b>")
    for symbol in ['NIFTY 50', 'NIFTY BANK']:
        if symbol not in prices:
            continue
        
        price = prices[symbol]
        alert_data = calculate_alerts(symbol, price)
        
        if alert_data:
            arrow = "🟢" if alert_data['change'] > 0 else "🔴"
            alert_emoji = alert_data['alert'] if alert_data['alert'] else ""
            messages.append(
                f"{arrow} <b>{symbol}</b>: ₹{price:,.2f}\n"
                f"   📈 Change: {alert_data['change']:+,.2f} ({alert_data['change_pct']:+.2f}%) {alert_emoji}\n"
                f"   📊 H: {alert_data['high']:,.2f} | L: {alert_data['low']:,.2f}"
            )
        else:
            messages.append(f"• {symbol}: ₹{price:,.2f}")
    
    messages.append("\n🔷 <b>STOCKS</b>")
    for symbol in ['TCS', 'HDFCBANK', 'SBIN', 'RELIANCE']:
        if symbol not in prices:
            continue
        
        price = prices[symbol]
        alert_data = calculate_alerts(symbol, price)
        
        if alert_data:
            arrow = "🟢" if alert_data['change'] > 0 else "🔴"
            alert_emoji = alert_data['alert'] if alert_data['alert'] else ""
            messages.append(
                f"{arrow} <b>{symbol}</b>: ₹{price:,.2f}\n"
                f"   📈 Change: {alert_data['change']:+,.2f} ({alert_data['change_pct']:+.2f}%) {alert_emoji}\n"
                f"   📊 H: {alert_data['high']:,.2f} | L: {alert_data['low']:,.2f}"
            )
        else:
            messages.append(f"• {symbol}: ₹{price:,.2f}")
    
    messages.append(f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    messages.append("📡 Angel One API • Last 1 Hour Data")
    
    return "\n".join(messages)

def bot_loop():
    if not all(REQUIRED):
        logger.error('Missing required environment variables')
        return

    try:
        smartApi, authToken, refreshToken, feedToken = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
        logger.info("✅ Login successful!")
    except Exception as e:
        logger.exception('Login failed')
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    tele_send_http(TELE_CHAT_ID, 
        f"✅ <b>Bot Started!</b>\n\n"
        f"📊 Tracking: NIFTY 50, NIFTY BANK, TCS, HDFCBANK, SBIN, RELIANCE\n"
        f"⏱ Interval: {POLL_INTERVAL}s\n"
        f"📈 Historical: Last 1 hour\n"
        f"🔔 Alerts: >1% moves"
    )

    chart_counter = 0
    
    while True:
        try:
            # Get live prices
            prices = get_market_data_angel(smartApi)
            
            if prices and any(prices.values()):
                # Store in history
                store_price_history(prices)
                
                # Format message
                message = format_alert_message(prices)
                
                # Send charts every 5 updates (5 minutes if 1 min interval)
                if chart_counter % 5 == 0:
                    # Create and send chart for NIFTY 50
                    chart_file = create_chart('NIFTY 50')
                    if chart_file:
                        tele_send_http(TELE_CHAT_ID, message, chart_file)
                    else:
                        tele_send_http(TELE_CHAT_ID, message)
                else:
                    tele_send_http(TELE_CHAT_ID, message)
                
                chart_counter += 1
                logger.info(f'Update sent (counter: {chart_counter})')
            else:
                logger.error("No data received")
                tele_send_http(TELE_CHAT_ID, "⚠️ Unable to fetch data")
            
        except Exception as e:
            logger.exception(f"Error in bot loop: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error: {e}")
        
        time.sleep(POLL_INTERVAL)

# Start bot
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    status = {
        'bot_thread_alive': thread.is_alive(),
        'poll_interval': POLL_INTERVAL,
        'smartapi_available': SmartConnect is not None,
        'history_symbols': list(price_history.keys()),
        'history_counts': {k: len(v) for k, v in price_history.items()}
    }
    return jsonify(status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
