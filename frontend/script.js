
        const { useState, useEffect, useCallback, useRef } = React;
        const BACKEND_URL = "http://127.0.0.1:5000";
        
        // Toast Component
        const Toast = ({ message, type, onClose }) => {
            useEffect(() => {
                const timer = setTimeout(onClose, 4000);
                return () => clearTimeout(timer);
            }, [onClose]);

            const bgColor = {
                success: 'bg-green-500',
                error: 'bg-red-500',
                warning: 'bg-yellow-500',
                info: 'bg-blue-500'
            }[type] || 'bg-gray-500';

            const icon = {
                success: '✓',
                error: '✕',
                warning: '⚠',
                info: 'ℹ'
            }[type] || 'ℹ';

            return (
                <div className={`fixed top-4 right-4 z-50 flex items-center space-x-3 ${bgColor} text-white px-4 py-3 rounded-lg shadow-lg animate-slideDown`}>
                    <span className="text-xl">{icon}</span>
                    <span className="font-medium">{message}</span>
                    <button onClick={onClose} className="ml-4 hover:opacity-75 transition-opacity">
                        ✕
                    </button>
                </div>
            );
        };

        // Progress Bar Component
        const TokenProgress = ({ expiresAt }) => {
            const [remaining, setRemaining] = useState(0);
            const [percentage, setPercentage] = useState(100);

            useEffect(() => {
                if (!expiresAt) return;

                const interval = setInterval(() => {
                    const now = Math.floor(Date.now() / 1000);
                    const timeLeft = Math.max(0, expiresAt - now);
                    const totalTime = 3600; // JWT_EXP from backend
                    const pct = (timeLeft / totalTime) * 100;
                    
                    setRemaining(timeLeft);
                    setPercentage(pct);

                    if (timeLeft === 0) {
                        clearInterval(interval);
                    }
                }, 1000);

                return () => clearInterval(interval);
            }, [expiresAt]);

            const formatTime = (seconds) => {
                const mins = Math.floor(seconds / 60);
                const secs = seconds % 60;
                return `${mins}m ${secs}s`;
            };

            const getProgressColor = () => {
                if (percentage > 50) return 'bg-green-500';
                if (percentage > 20) return 'bg-yellow-500';
                return 'bg-red-500';
            };

            if (!expiresAt) return null;

            return (
                <div className="w-full">
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-sm text-gray-600 dark:text-gray-400">Token Expiry</span>
                        <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                            {remaining > 0 ? formatTime(remaining) : 'Expired'}
                        </span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
                        <div 
                            className={`h-full ${getProgressColor()} transition-all duration-1000 ease-linear rounded-full`}
                            style={{ width: `${percentage}%` }}
                        />
                    </div>
                </div>
            );
        };

        // QR Code Modal Component
        const QRModal = ({ isOpen, onClose }) => {
            const canvasRef = useRef(null);

            useEffect(() => {
                if (isOpen && canvasRef.current) {
                    // Generate a mock WalletConnect URI for demo
                    const wcUri = `wc:8a5e5bdc-a0e4-4702-ba63-8f1a5655744f@1?bridge=https%3A%2F%2Fbridge.walletconnect.org&key=41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a`;
                    
                    QRCode.toCanvas(canvasRef.current, wcUri, {
                        width: 256,
                        margin: 2,
                        color: {
                            dark: '#000000',
                            light: '#FFFFFF'
                        }
                    });
                }
            }, [isOpen]);

            if (!isOpen) return null;

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 animate-fadeIn">
                    <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 max-w-sm w-full mx-4 animate-slideUp">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-xl font-semibold text-gray-800 dark:text-white">
                                Scan with WalletConnect
                            </h3>
                            <button 
                                onClick={onClose}
                                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
                            >
                                ✕
                            </button>
                        </div>
                        <div className="flex justify-center mb-4">
                            <canvas ref={canvasRef} className="rounded-lg" />
                        </div>
                        <p className="text-sm text-center text-gray-600 dark:text-gray-400">
                            Scan this QR code with your mobile wallet to connect
                        </p>
                    </div>
                </div>
            );
        };

        // Main App Component
        const WalletAuth = () => {
            const [isDark, setIsDark] = useState(false);
            const [toast, setToast] = useState(null);
            const [loading, setLoading] = useState(false);
            const [walletAddress, setWalletAddress] = useState(null);
            const [token, setToken] = useState(null);
            const [tokenExpiry, setTokenExpiry] = useState(null);
            const [showQR, setShowQR] = useState(false);
            const [protectedData, setProtectedData] = useState(null);
            const [showWallet, setShowWallet] = useState(false);

            const revealWallet = () => {
                if (!walletAddress) {
                    showToast("Please connect your wallet first", "warning");
                    return;
                }
                setShowWallet(!showWallet);
            };
            useEffect(() => {
                // Check for existing token on load
                const storedToken = localStorage.getItem('wallet_2fa_token');
                if (storedToken) {
                    const payload = parseJwt(storedToken);
                    if (payload && payload.exp > Math.floor(Date.now() / 1000)) {
                        setToken(storedToken);
                        setTokenExpiry(payload.exp);
                        setWalletAddress(payload.sub);
                        showToast('Session restored', 'info');
                    } else {
                        localStorage.removeItem('wallet_2fa_token');
                    }
                }

                // Apply dark mode preference
                if (isDark) {
                    document.documentElement.classList.add('dark');
                } else {
                    document.documentElement.classList.remove('dark');
                }
            }, [isDark]);

            const parseJwt = (token) => {
                try {
                    const base64Url = token.split('.')[1];
                    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                    const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
                        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
                    ).join(''));
                    return JSON.parse(jsonPayload);
                } catch (e) {
                    return null;
                }
            };

            const showToast = (message, type = 'info') => {
                setToast({ message, type });
            };

            const connectWallet = async () => {
                if (!window.ethereum) {
                    showToast('Please install MetaMask to continue', 'error');
                    return;
                }

                setLoading(true);
                try {
                    // Request accounts
                    await window.ethereum.request({ method: 'eth_requestAccounts' });
                    const provider = new ethers.providers.Web3Provider(window.ethereum);
                    const signer = provider.getSigner();
                    const address = await signer.getAddress();

                    // Get nonce
                    const nonceResponse = await fetch(`${BACKEND_URL}/auth/nonce`);
                    if (!nonceResponse.ok) throw new Error('Failed to fetch nonce');
                    const { nonce } = await nonceResponse.json();

                    // Sign message
                    const signature = await signer.signMessage(nonce);

                    // Verify signature
                    const verifyResponse = await fetch(`${BACKEND_URL}/auth/verify`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ address, signature, nonce })
                    });

                    if (!verifyResponse.ok) {
                        const error = await verifyResponse.json();
                        throw new Error(error.error || 'Verification failed');
                    }

                    const { token: jwtToken, expires_in } = await verifyResponse.json();
                    
                    // Store token and update state
                    localStorage.setItem('wallet_2fa_token', jwtToken);
                    const payload = parseJwt(jwtToken);
                    
                    setToken(jwtToken);
                    setTokenExpiry(payload.exp);
                    setWalletAddress(address.toLowerCase());
                    showToast('Successfully authenticated!', 'success');
                    
                } catch (error) {
                    showToast(error.message || 'Authentication failed', 'error');
                    console.error('Auth error:', error);
                } finally {
                    setLoading(false);
                }
            };

            const checkProtected = async () => {
                if (!token) {
                    showToast('Please login first', 'warning');
                    return;
                }

                setLoading(true);
                try {
                    const response = await fetch(`${BACKEND_URL}/protected`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    const data = await response.json();
                    
                    if (response.ok) {
                        setProtectedData(data);
                        showToast('Protected route accessed!', 'success');
                    } else {
                        throw new Error(data.error || 'Access denied');
                    }
                } catch (error) {
                    showToast(error.message || 'Failed to access protected route', 'error');
                } finally {
                    setLoading(false);
                }
            };

            const refreshToken = async () => {
                if (!token) {
                    showToast('No active session to refresh', 'warning');
                    return;
                }

                setLoading(true);
                try {
                    const response = await fetch(`${BACKEND_URL}/auth/refresh`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.error || 'Refresh failed');
                    }

                    const { token: newToken } = await response.json();
                    localStorage.setItem('wallet_2fa_token', newToken);
                    const payload = parseJwt(newToken);
                    
                    setToken(newToken);
                    setTokenExpiry(payload.exp);
                    showToast('Token refreshed successfully!', 'success');
                } catch (error) {
                    showToast(error.message || 'Failed to refresh token', 'error');
                } finally {
                    setLoading(false);
                }
            };

            const logout = () => {
                localStorage.removeItem('wallet_2fa_token');
                setToken(null);
                setTokenExpiry(null);
                setWalletAddress(null);
                setProtectedData(null);
                showToast('Logged out successfully', 'info');
            };

            return (
            <div className="min-h-screen p-4">
                {toast && (
                <Toast 
                    message={toast.message} 
                    type={toast.type} 
                    onClose={() => setToast(null)} 
                />
                )}

                <QRModal isOpen={showQR} onClose={() => setShowQR(false)} />

                <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-6 mb-6 animate-fadeIn">
                    <div className="flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                        Wallet 2FA
                        </h1>
                        <p className="text-gray-600 dark:text-gray-400 mt-1">
                        Secure authentication with Web3 wallets
                        </p>
                    </div>
                   
                    </div>
                </div>
                
                {/* Show Wallet Info Button */}
                {walletAddress && (
                    <div className="text-center mb-6">
                    <button
                        onClick={revealWallet}
                        className="py-2 px-6 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700 transform hover:scale-105 transition-all duration-200"
                    >
                        {showWallet ? 'Hide Wallet Address' : 'Show Wallet Address'}
                    </button>
                    

                    {showWallet && (
                        <p className="mt-2 text-mono text-sm text-gray-200 bg-gray-700 rounded p-2 break-words">
                        {walletAddress}
                        </p>
                    )}
                    </div>
                )}

                {/* Main Content */}
                <div className="grid md:grid-cols-2 gap-6">
                    {/* Authentication Panel */}
                    <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-6 animate-fadeIn" style={{animationDelay: '0.1s'}}>
                    <h2 className="text-xl font-semibold text-gray-800 dark:text-white mb-4">
                        Authentication
                    </h2>

                    {!walletAddress ? (
                        <div className="space-y-4">
                        <button
                            onClick={connectWallet}
                            disabled={loading}
                            className="w-full py-3 px-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium rounded-lg hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                        >
                            {loading ? (
                            <span className="animate-pulse">Connecting...</span>
                            ) : (
                            <>
                                <span>🦊</span>
                                <span>Connect with MetaMask</span>
                            </>
                            )}
                        </button>

                        <button
                            onClick={() => setShowQR(true)}
                            className="w-full py-3 px-4 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white font-medium rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transform hover:scale-105 transition-all duration-200 flex items-center justify-center space-x-2"
                        >
                            <span>📱</span>
                            <span>WalletConnect (QR)</span>
                        </button>
                        </div>
                    ) : (
                        <div className="space-y-4">
                        <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Connected Wallet</p>
                            <p className="font-mono text-sm text-gray-800 dark:text-gray-200 break-all">
                            {walletAddress}
                            </p>
                        </div>

                        <TokenProgress expiresAt={tokenExpiry} />

                        <div className="grid grid-cols-2 gap-3">
                            <button
                            onClick={refreshToken}
                            disabled={loading}
                            className="py-2 px-4 bg-blue-500 text-white font-medium rounded-lg hover:bg-blue-600 transform hover:scale-105 transition-all duration-200 disabled:opacity-50"
                            >
                            🔄 Refresh
                            </button>
                            <button
                            onClick={logout}
                            className="py-2 px-4 bg-red-500 text-white font-medium rounded-lg hover:bg-red-600 transform hover:scale-105 transition-all duration-200"
                            >
                            🚪 Logout
                            </button>
                        </div>
                        </div>
                    )}
                    </div>

                    {/* Protected Route Test */}
                    <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-6 animate-fadeIn" style={{animationDelay: '0.2s'}}>
                    <h2 className="text-xl font-semibold text-gray-800 dark:text-white mb-4">
                        Protected Route Test
                    </h2>

                    <button
                        onClick={checkProtected}
                        disabled={loading || !token}
                        className="w-full py-3 px-4 bg-green-500 text-white font-medium rounded-lg hover:bg-green-600 transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed mb-4"
                    >
                        🔐 Access Protected Route
                    </button>

                    {protectedData && (
                        <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg animate-slideUp">
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Response:</p>
                        <pre className="text-xs text-gray-800 dark:text-gray-200 overflow-x-auto">
                            {JSON.stringify(protectedData, null, 2)}
                        </pre>
                        </div>
                    )}

                    {!token && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
                        Please connect your wallet first
                        </p>
                    )}
                    </div>
                </div>
                </div>
            </div>
            );

        };

        // Render the app
        ReactDOM.render(<WalletAuth />, document.getElementById('root'));
    