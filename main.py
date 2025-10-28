import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import io

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
logger = logging.getLogger('angel-option-chain-bot')

# Load config from env
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 300)  # 5 min default for charts

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# Symbol configurations
SYMBOLS_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 21,
        'lot_size': 25,
        'name_in_instruments': 'NIFTY'
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 100,
        'strikes_count': 21,
        'lot_size': 15,
        'name_in_instruments': 'BANKNIFTY'
    },
    'MIDCPNIFTY': {
        'spot_token': '99926037',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 25,
        'strikes_count': 21,
        'lot_size': 75,
        'name_in_instruments': 'MIDCPNIFTY'
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 21,
        'lot_size': 25,
        'name_in_instruments': 'FINNIFTY'
    },
    'SENSEX': {
        'spot_token': '99919000',
        'exchange': 'BSE',
        'exch_seg': 'BFO',
        'strike_gap': 100,
        'strikes_count': 21,
        'lot_size': 10,
        'name_in_instruments': 'SENSEX'
    },
    'HDFCBANK': {
        'spot_token': '1333',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 20,
        'strikes_count': 21,
        'lot_size': 550,
        'name_in_instruments': 'HDFCBANK'
    }
}

# Store previous OI data
previous_oi = defaultdict(dict)

def tele_send_http(chat_id: str, text: str):
    """Send text message to Telegram"""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set')
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Failed to send message: {e}')
        return False

def tele_send_photo(chat_id: str, photo_bytes: bytes, caption: str = ""):
    """Send photo to Telegram"""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set')
            return False
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        files = {'photo': ('chart.png', photo_bytes, 'image/png')}
        data = {'chat_id': chat_id, 'caption': caption, 'parse_mode': 'HTML'}
        r = requests.post(url, files=files, data=data, timeout=30)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Failed to send photo: {e}')
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
    logger.info(f"✅ Login successful!")
    try:
        feedToken = smartApi.getfeedToken()
    except Exception as e:
        logger.warning(f"Feed token failed: {e}")
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except:
        pass
    return smartApi, authToken, refreshToken, feedToken

def download_instruments(smartApi):
    """Download instrument master file"""
    try:
        logger.info("📥 Downloading instruments...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ Downloaded {len(instruments)} instruments")
            
            # Debug: Check what names exist for each symbol
            for symbol, config in SYMBOLS_CONFIG.items():
                exact = [i for i in instruments if i.get('name') == config['name_in_instruments'] and i.get('exch_seg') == config['exch_seg']]
                logger.info(f"   {symbol}: {len(exact)} contracts with name '{config['name_in_instruments']}'")
                
                if len(exact) == 0:
                    partial = [i for i in instruments if symbol in i.get('name', '') and i.get('exch_seg') == config['exch_seg']]
                    if partial:
                        sample_name = partial[0].get('name')
                        logger.info(f"   Found partial matches with name: '{sample_name}'")
                        config['name_in_instruments'] = sample_name
            
            return instruments
        else:
            logger.error(f"Failed to download instruments: {response.status_code}")
        return None
    except Exception as e:
        logger.exception(f"❌ Failed to download instruments: {e}")
        return None

def find_nearest_expiry(instruments, symbol, exch_seg, name_in_inst):
    """Find nearest available expiry (including today if not expired yet)"""
    try:
        expiries = set()
        for inst in instruments:
            if inst.get('name') == name_in_inst and inst.get('exch_seg') == exch_seg and inst.get('expiry'):
                expiries.add(inst.get('expiry'))
        
        if not expiries:
            logger.warning(f"No expiries for {symbol}")
            return None
        
        now = datetime.now()
        # Consider expiry valid until 3:30 PM on expiry day
        cutoff_time = now.replace(hour=15, minute=30, second=0, microsecond=0)
        
        future_expiries = []
        
        for exp_str in expiries:
            try:
                exp_date = None
                for fmt in ['%d%b%Y', '%d%b%y']:
                    try:
                        exp_date = datetime.strptime(exp_str, fmt)
                        break
                    except:
                        continue
                
                if exp_date:
                    # Set expiry time to 3:30 PM
                    exp_datetime = exp_date.replace(hour=15, minute=30, second=0, microsecond=0)
                    
                    # Include if expiry hasn't passed yet
                    if exp_datetime >= now:
                        future_expiries.append((exp_datetime, exp_str))
            except:
                continue
        
        if not future_expiries:
            logger.warning(f"No future expiries for {symbol}")
            return None
        
        future_expiries.sort()
        nearest = future_expiries[0][1]
        nearest_date = future_expiries[0][0]
        
        # Check if today's expiry
        is_today = nearest_date.date() == now.date()
        time_suffix = " (TODAY)" if is_today else ""
        
        logger.info(f"📅 {symbol}: {nearest}{time_suffix}")
        return nearest
    except Exception as e:
        logger.exception(f"Error finding expiry: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price, strike_gap, strikes_count, exch_seg, name_in_inst):
    """Find option tokens"""
    if not instruments or not target_expiry:
        return []
    
    atm = round(current_price / strike_gap) * strike_gap
    strikes = []
    half = strikes_count // 2
    for i in range(-half, half + 1):
        strikes.append(atm + (i * strike_gap))
    
    option_tokens = []
    for inst in instruments:
        if inst.get('name') == name_in_inst and inst.get('expiry') == target_expiry and inst.get('exch_seg') == exch_seg:
            try:
                strike = float(inst.get('strike', '0')) / 100
            except:
                continue
            
            if strike > 0 and strike in strikes:
                symbol_name = inst.get('symbol', '')
                option_type = 'CE' if 'CE' in symbol_name else 'PE'
                token = inst.get('token')
                option_tokens.append({
                    'strike': strike,
                    'type': option_type,
                    'token': token,
                    'symbol': symbol_name,
                    'expiry': target_expiry
                })
    
    logger.info(f"✅ {symbol}: {len(option_tokens)} options found")
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_data(smartApi, option_tokens, exch_seg):
    """Fetch option market data"""
    try:
        if not option_tokens:
            return {}
        
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        all_tokens = [opt['token'] for opt in option_tokens]
        result = {}
        
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            payload = {"mode": "FULL", "exchangeTokens": {exch_seg: batch}}
            
            response = requests.post(
                'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                json=payload, headers=headers, timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status'):
                    for item in data.get('data', {}).get('fetched', []):
                        token = item.get('symbolToken', '')
                        result[token] = {
                            'ltp': float(item.get('ltp', 0)),
                            'oi': int(item.get('opnInterest', 0)),
                            'volume': int(item.get('tradeVolume', 0)),
                        }
            time.sleep(0.3)
        
        return result
    except Exception as e:
        logger.exception(f"Failed to fetch data: {e}")
        return {}

def get_spot_prices(smartApi):
    """Get spot prices"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        nse_tokens = []
        bse_tokens = []
        
        for config in SYMBOLS_CONFIG.values():
            if config['exchange'] == 'NSE':
                nse_tokens.append(config['spot_token'])
            else:
                bse_tokens.append(config['spot_token'])
        
        payload = {"mode": "LTP", "exchangeTokens": {"NSE": nse_tokens, "BSE": bse_tokens}}
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload, headers=headers, timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                for item in data.get('data', {}).get('fetched', []):
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    for symbol, config in SYMBOLS_CONFIG.items():
                        if config['spot_token'] == token:
                            result[symbol] = ltp
                            break
                return result
        return {}
    except Exception as e:
        logger.exception(f"Failed to fetch spots: {e}")
        return {}

def get_current_ltp(smartApi, token, exchange):
    """Get current LTP for a token"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        exch_key = 'NSE' if exchange == 'NSE' else 'BSE'
        payload = {"mode": "LTP", "exchangeTokens": {exch_key: [token]}}
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload, headers=headers, timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                fetched = data.get('data', {}).get('fetched', [])
                if fetched:
                    return float(fetched[0].get('ltp', 0))
        return None
    except Exception as e:
        logger.warning(f"Failed to get current LTP: {e}")
        return None

def get_historical_candles_with_current(smartApi, symbol, token, exchange):
    """Fetch intraday + historical candles + current live candle"""
    try:
        logger.info(f"📊 Fetching candles for {symbol}...")
        
        now = datetime.now()
        all_candles = []
        
        # STEP 1: Get today's intraday candles (9:15 AM to current time)
        today_start = now.replace(hour=9, minute=15, second=0, microsecond=0)
        if now > today_start:
            try:
                params_today = {
                    "exchange": exchange,
                    "symboltoken": token,
                    "interval": "FIFTEEN_MINUTE",
                    "fromdate": today_start.strftime("%Y-%m-%d %H:%M"),
                    "todate": now.strftime("%Y-%m-%d %H:%M")
                }
                
                response_today = smartApi.getCandleData(params_today)
                
                if response_today and response_today.get('status'):
                    today_candles = response_today.get('data', [])
                    logger.info(f"✅ Got {len(today_candles)} today's candles for {symbol}")
                    all_candles.extend(today_candles)
            except Exception as e:
                logger.warning(f"Could not fetch today's candles: {e}")
        
        # STEP 2: Get last 30 days historical candles (excluding today)
        yesterday = now - timedelta(days=1)
        from_date = now - timedelta(days=30)
        
        params_historical = {
            "exchange": exchange,
            "symboltoken": token,
            "interval": "FIFTEEN_MINUTE",
            "fromdate": from_date.strftime("%Y-%m-%d 09:15"),
            "todate": yesterday.strftime("%Y-%m-%d 15:30")
        }
        
        response_hist = smartApi.getCandleData(params_historical)
        
        if response_hist and response_hist.get('status'):
            hist_candles = response_hist.get('data', [])
            logger.info(f"✅ Got {len(hist_candles)} historical candles for {symbol}")
            
            # Combine historical + today's candles
            all_candles = hist_candles + all_candles
        
        if not all_candles:
            logger.warning(f"No candle data for {symbol}")
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame(all_candles, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Remove duplicates and sort
        df = df.drop_duplicates(subset=['timestamp']).sort_values('timestamp').reset_index(drop=True)
        
        # Take last 499 (to make room for current candle)
        if len(df) > 499:
            df = df.tail(499)
        
        logger.info(f"✅ Total candles: {len(df)} for {symbol}")
        
        # STEP 3: ADD CURRENT LIVE CANDLE
        try:
            current_ltp = get_current_ltp(smartApi, token, exchange)
            if current_ltp:
                last_candle = df.iloc[-1] if len(df) > 0 else None
                last_timestamp = last_candle['timestamp'] if last_candle is not None else now
                
                # Only add if current time is significantly after last candle
                if (now - last_timestamp).total_seconds() > 60:
                    current_candle = {
                        'timestamp': now,
                        'open': last_candle['close'] if last_candle is not None else current_ltp,
                        'high': current_ltp,
                        'low': current_ltp,
                        'close': current_ltp,
                        'volume': 0
                    }
                    
                    df = pd.concat([df, pd.DataFrame([current_candle])], ignore_index=True)
                    logger.info(f"✅ Added current candle: LTP={current_ltp}")
        except Exception as e:
            logger.warning(f"Could not add current candle: {e}")
        
        return df
    except Exception as e:
        logger.exception(f"Failed to fetch candles: {e}")
        return None

def create_candlestick_chart(df, symbol, spot_price):
    """Create TradingView-style candlestick chart with current price"""
    try:
        fig, ax = plt.subplots(figsize=(16, 9), facecolor='white')
        ax.set_facecolor('white')
        
        # Plot candlesticks
        for idx, row in df.iterrows():
            open_price = row['open']
            high_price = row['high']
            low_price = row['low']
            close_price = row['close']
            
            # Color: Green if close > open, Red otherwise
            color = '#26a69a' if close_price >= open_price else '#ef5350'
            
            # Special styling for last candle (current/live)
            is_last = (idx == len(df) - 1)
            linewidth = 2 if is_last else 1
            
            # Draw high-low line
            ax.plot([idx, idx], [low_price, high_price], color=color, linewidth=linewidth)
            
            # Draw candle body
            body_height = abs(close_price - open_price)
            body_bottom = min(open_price, close_price)
            
            # Hollow candle for current/live candle
            if is_last:
                rect = Rectangle((idx - 0.4, body_bottom), 0.8, body_height, 
                               facecolor='none', edgecolor=color, linewidth=2)
            else:
                rect = Rectangle((idx - 0.4, body_bottom), 0.8, body_height, 
                               facecolor=color, edgecolor=color, linewidth=0)
            ax.add_patch(rect)
        
        # Add current price annotation
        last_price = df.iloc[-1]['close']
        ax.annotate(f'₹{last_price:,.2f}', 
                   xy=(len(df)-1, last_price),
                   xytext=(10, 0), textcoords='offset points',
                   bbox=dict(boxstyle='round,pad=0.5', facecolor='yellow', alpha=0.7),
                   fontsize=11, fontweight='bold',
                   arrowprops=dict(arrowstyle='->', color='red', lw=1.5))
        
        # Styling
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Price', fontsize=12, fontweight='bold')
        
        current_time = datetime.now().strftime('%H:%M:%S')
        ax.set_title(f'{symbol} - 15 Min Chart | Spot: ₹{spot_price:,.2f} | {current_time}', 
                    fontsize=16, fontweight='bold', pad=20)
        
        # Grid
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        ax.set_axisbelow(True)
        
        # X-axis labels (show every 50th candle + last one)
        step = max(1, len(df) // 10)
        xticks = list(range(0, len(df), step))
        if len(df) - 1 not in xticks:
            xticks.append(len(df) - 1)  # Always show last timestamp
        
        xticklabels = [df.iloc[i]['timestamp'].strftime('%d-%b %H:%M') for i in xticks]
        ax.set_xticks(xticks)
        ax.set_xticklabels(xticklabels, rotation=45, ha='right')
        
        plt.tight_layout()
        
        # Save to bytes
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, facecolor='white')
        buf.seek(0)
        plt.close(fig)
        
        return buf.getvalue()
    except Exception as e:
        logger.exception(f"Failed to create chart: {e}")
        return None

def format_volume(vol):
    if vol >= 10000000:
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def format_option_chain(symbol, spot_price, expiry, option_data, market_data, lot_size):
    """Format option chain message"""
    msg = []
    msg.append(f"📊 <b>{symbol}</b>")
    msg.append(f"💰 ₹{spot_price:,.1f} | 📅 {expiry} | Lot: {lot_size}\n")
    
    strikes = {}
    for opt in option_data:
        strike = opt['strike']
        if strike not in strikes:
            strikes[strike] = {'CE': {}, 'PE': {}}
        
        token = opt['token']
        mdata = market_data.get(token, {})
        
        prev_oi = previous_oi.get(symbol, {}).get(token, 0)
        current_oi = mdata.get('oi', 0)
        oi_change = current_oi - prev_oi
        
        if symbol not in previous_oi:
            previous_oi[symbol] = {}
        previous_oi[symbol][token] = current_oi
        
        strikes[strike][opt['type']] = {**mdata, 'oi_change': oi_change}
    
    msg.append("<code>CE           |STRIKE|PE</code>")
    msg.append("<code>LTP OI  Vol  |      |LTP OI  Vol</code>")
    msg.append("─" * 40)
    
    total_ce_oi = 0
    total_pe_oi = 0
    
    for strike in sorted(strikes.keys()):
        ce = strikes[strike].get('CE', {})
        pe = strikes[strike].get('PE', {})
        
        ce_ltp = ce.get('ltp', 0)
        ce_oi = ce.get('oi', 0)
        ce_vol = ce.get('volume', 0)
        
        pe_ltp = pe.get('ltp', 0)
        pe_oi = pe.get('oi', 0)
        pe_vol = pe.get('volume', 0)
        
        total_ce_oi += ce_oi
        total_pe_oi += pe_oi
        
        ce_oi_str = f"{ce_oi//1000}k" if ce_oi >= 1000 else str(ce_oi) if ce_oi > 0 else "-"
        pe_oi_str = f"{pe_oi//1000}k" if pe_oi >= 1000 else str(pe_oi) if pe_oi > 0 else "-"
        
        ce_vol_str = format_volume(ce_vol) if ce_vol > 0 else "-"
        pe_vol_str = format_volume(pe_vol) if pe_vol > 0 else "-"
        
        ce_str = f"{ce_ltp:>3.0f} {ce_oi_str:>4} {ce_vol_str:>4}" if ce_ltp > 0 else "              "
        pe_str = f"{pe_ltp:>3.0f} {pe_oi_str:>4} {pe_vol_str:>4}" if pe_ltp > 0 else "              "
        
        msg.append(f"<code>{ce_str}|{int(strike):>6}|{pe_str}</code>")
    
    msg.append("─" * 40)
    
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        msg.append(f"<b>PCR:</b> {pcr:.2f} | OI: CE {format_volume(total_ce_oi)} PE {format_volume(total_pe_oi)}")
    
    msg.append(f"🕐 {time.strftime('%H:%M:%S')}")
    
    return "\n".join(msg)

def bot_loop():
    if not all(REQUIRED):
        logger.error('❌ Missing env variables')
        return

    try:
        smartApi, *_ = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
    except Exception as e:
        logger.exception('❌ Login failed')
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    tele_send_http(TELE_CHAT_ID, "✅ <b>Option Chain + Live Chart Bot Started!</b>\n⏱ Updates every 5 min\n\n⏳ Loading...")
    
    instruments = download_instruments(smartApi)
    if not instruments:
        logger.error("No instruments")
        return
    
    iteration = 0
    last_expiry_check = 0
    expiry_check_interval = 3600  # Re-check expiries every hour
    
    # Initial expiry discovery
    expiries = {}
    for symbol, config in SYMBOLS_CONFIG.items():
        exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
        if exp:
            expiries[symbol] = exp
    
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}\n🔄 Iteration #{iteration}\n{'='*50}")
            
            # Refresh expiries periodically (every hour) or if it's been a while
            current_time = time.time()
            if current_time - last_expiry_check > expiry_check_interval:
                logger.info("🔄 Refreshing expiries...")
                for symbol, config in SYMBOLS_CONFIG.items():
                    new_exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
                    if new_exp and new_exp != expiries.get(symbol):
                        old_exp = expiries.get(symbol, 'None')
                        expiries[symbol] = new_exp
                        msg = f"📅 {symbol} expiry changed: {old_exp} → {new_exp}"
                        logger.info(msg)
                        tele_send_http(TELE_CHAT_ID, f"<b>{msg}</b>")
                    elif new_exp:
                        expiries[symbol] = new_exp
                last_expiry_check = current_time
            
            spot_prices = get_spot_prices(smartApi)
            
            for symbol, config in SYMBOLS_CONFIG.items():
                if symbol not in expiries or symbol not in spot_prices:
                    continue
                
                spot_price = spot_prices[symbol]
                expiry = expiries[symbol]
                
                # Option chain
                option_tokens = find_option_tokens(
                    instruments, symbol, expiry, spot_price,
                    config['strike_gap'], config['strikes_count'],
                    config['exch_seg'], config['name_in_instruments']
                )
                
                if option_tokens:
                    market_data = get_option_data(smartApi, option_tokens, config['exch_seg'])
                    if market_data:
                        msg = format_option_chain(symbol, spot_price, expiry, option_tokens, market_data, config['lot_size'])
                        tele_send_http(TELE_CHAT_ID, msg)
                        time.sleep(2)
                
                # Live Candlestick chart with current data
                candle_df = get_historical_candles_with_current(smartApi, symbol, config['spot_token'], config['exchange'])
                if candle_df is not None and len(candle_df) > 0:
                    chart_bytes = create_candlestick_chart(candle_df, symbol, spot_price)
                    if chart_bytes:
                        tele_send_photo(TELE_CHAT_ID, chart_bytes, f"📊 {symbol} Live Chart")
                        logger.info(f"✅ {symbol} chart sent")
                        time.sleep(2)
            
            logger.info(f"✅ Iteration #{iteration} done. Sleep {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    return jsonify({
        'service': 'Angel One Option Chain + Live Chart Bot',
        'bot_alive': thread.is_alive(),
        'symbols': list(SYMBOLS_CONFIG.keys()),
        'features': ['Option Chain', 'Live Candlestick Charts', 'Real-time OI Tracking', 'Auto Expiry Selection'],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
