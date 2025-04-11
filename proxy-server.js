/**
 * Subworld Network Proxy
 * 
 * This proxy server acts as a secure bridge between HTTPS clients
 * and HTTP Subworld network nodes, with integrated TURN server functionality.
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const Turn = require('node-turn'); // Add this import for TURN server

// Configuration
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ENABLE_DETAILED_LOGGING = process.env.ENABLE_DETAILED_LOGGING === 'true' || false;
const TURN_PORT = process.env.TURN_PORT || 3478; // TURN server port

// Create Express app
const app = express();
const server = http.createServer(app);

try {
  // Create and configure TURN server
  const turnServer = new Turn({
    // TURN server configuration
    authMech: 'long-term',
    credentials: {
      username: "subworlduser", 
      password: "subworldpass"   
    },
    realm: 'subworld.turn',
    debugLevel: 'ERROR',
    listenPort: TURN_PORT
  });

  // Start the TURN server with proper error handling
  if (typeof turnServer.start === 'function') {
    const startResult = turnServer.start();
    if (startResult && typeof startResult.then === 'function') {
      startResult
        .then(() => {
          console.log(`TURN server started on port ${TURN_PORT}`);
        })
        .catch(error => {
          console.error('Failed to start TURN server:', error);
        });
    } else {
      console.log(`TURN server started on port ${TURN_PORT} (synchronous mode)`);
    }
  } else {
    console.error('TURN server start method not available, running in proxy-only mode');
  }
} catch (error) {
  console.error('Failed to initialize TURN server:', error);
  console.log('Continuing in proxy-only mode without TURN functionality');
}

// Initialize Socket.io
const io = new Server(server, {
  cors: {
    origin: '*', // In production, restrict this to your app domains
    methods: ['GET', 'POST'],
  }
});

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1500, // limit each IP to 1500 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Apply rate limiting to all routes
app.use(limiter);

// CORS configuration
app.use(cors({
  origin: '*', // In production, restrict this to your app domains
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  if (ENABLE_DETAILED_LOGGING) {
    console.log(`[${timestamp}] ${req.method} ${req.url} - IP: ${req.ip}`);
  } else {
    console.log(`[${timestamp}] ${req.method} ${req.url}`);
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// New endpoint to get TURN server credentials
app.get('/turn-credentials', (req, res) => {
  // Get current server IP or domain
  const serverUrl = req.get('host');
  const protocol = req.protocol;
  
  // Create a username that expires after 24 hours (recommended for production)
  // For simplicity, we're using a fixed username and password here
  // In production, use time-limited credentials
  
  const credentials = {
    iceServers: [
      {
        urls: [
          `turn:${serverUrl}:${TURN_PORT}?transport=udp`,
          `turn:${serverUrl}:${TURN_PORT}?transport=tcp`,
        ],
        username: "subworlduser",
        credential: "subworldpass"
      }
      // No backup servers - using only our own TURN server
    ],
    ttl: 86400 // 24 hours in seconds
  };
  
  res.status(200).json(credentials);
});

// Known nodes registry - expand this as needed
const KNOWN_NODES = {
  'bootstrap1': {
    name: 'Bootstrap Node',
    address: 'http://93.4.27.35:8080', // P2P port
    apiAddress: 'http://93.4.27.35:8081', // API port
    isBootstrap: true,
    description: 'Primary bootstrap node (93.4.27.35)'
  }
  // Add more nodes when available
};

// Node info endpoint - returns available nodes list
app.get('/nodes', (req, res) => {
  const nodesList = Object.entries(KNOWN_NODES).map(([id, node]) => ({
    id,
    name: node.name,
    address: node.address,
    apiAddress: node.apiAddress,
    isOnline: true, // Assume online by default
    isBootstrap: !!node.isBootstrap,
    description: node.description || ''
  }));
  
  res.status(200).json({ nodes: nodesList });
});

// Node-specific info endpoint
app.get('/node/:nodeId/info', (req, res) => {
  const nodeId = req.params.nodeId;
  
  if (!KNOWN_NODES[nodeId]) {
    return res.status(404).json({ error: 'Node not found' });
  }
  
  res.status(200).json(KNOWN_NODES[nodeId]);
});

// Proxy to Subworld Network nodes
app.use('/api/:nodeId', (req, res, next) => {
  const nodeId = req.params.nodeId;
  
  // Get node info based on nodeId
  const nodeInfo = KNOWN_NODES[nodeId];
  
  if (!nodeInfo) {
    return res.status(404).json({ 
      error: 'Node not found', 
      message: `Node ID '${nodeId}' is not registered with this proxy` 
    });
  }
  
  // Use API address (port 8081) for API calls
  const targetHost = nodeInfo.apiAddress;
  
  // Create a proxy for this specific node
  const proxy = createProxyMiddleware({
    target: targetHost,
    changeOrigin: true,
    pathRewrite: {
      [`^/api/${nodeId}`]: '', // Remove the /api/nodeId prefix when forwarding
    },
    onProxyReq: (proxyReq, req, res) => {
      // Add custom headers
      proxyReq.setHeader('X-Forwarded-By', 'Subworld-Proxy');
      proxyReq.setHeader('X-Forwarded-Proto', 'https');
      
      // Log the proxied request if detailed logging is enabled
      if (ENABLE_DETAILED_LOGGING) {
        console.log(`Proxying to: ${targetHost}${req.path.replace(`/api/${nodeId}`, '')}`);
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      // Log response status if detailed logging is enabled
      if (ENABLE_DETAILED_LOGGING) {
        console.log(`Proxy response: ${proxyRes.statusCode} for ${req.method} ${req.url}`);
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      // Special handling for file downloads
      if (req.path.includes('/files/get')) {
        console.log('File download content-type:', proxyRes.headers['content-type']);
        
        // Ensure the content-type is properly preserved
        if (proxyRes.headers['content-type']) {
          res.setHeader('Content-Type', proxyRes.headers['content-type']);
        } else {
          res.setHeader('Content-Type', 'application/octet-stream');
        }
        
        // Ensure we don't modify binary responses
        delete proxyRes.headers['content-encoding'];
        
        // Disable any compression or transformation
        res.setHeader('Content-Encoding', 'identity');
      }
    },
    onProxyReq: (proxyReq, req, res) => {
      // Add custom headers
      proxyReq.setHeader('X-Forwarded-By', 'Subworld-Proxy');
      proxyReq.setHeader('X-Forwarded-Proto', 'https');
      
      // Log the proxied request if detailed logging is enabled
      if (ENABLE_DETAILED_LOGGING) {
        console.log(`Proxying to: ${targetHost}${req.path.replace(`/api/${nodeId}`, '')}`);
      }
    },
    
    onError: (err, req, res) => {
      console.error(`Proxy error for ${req.method} ${req.url}:`, err);
      res.status(502).json({ 
        error: 'Proxy error', 
        message: err.message,
        nodeId: nodeId,
        endpoint: req.path.replace(`/api/${nodeId}`, '')
      });
    }
  });
  
  proxy(req, res, next);
});

app.use('/voice', (req, res, next) => {
  // Higher priority for voice calls
  req.headers['X-Priority'] = 'high';
  
  // Always use the bootstrap node for voice calls
  const nodeId = 'bootstrap1';
  const nodeInfo = KNOWN_NODES[nodeId];
  
  if (!nodeInfo) {
    return res.status(500).json({
      error: 'Configuration error',
      message: 'Bootstrap node not configured'
    });
  }
  
  // Target the bootstrap node with minimal latency
  const targetHost = nodeInfo.apiAddress;
  const proxy = createProxyMiddleware({
    target: targetHost,
    changeOrigin: true,
    pathRewrite: {
      '^/voice': '/voice',
    },
    proxyTimeout: 5000, // Short timeout for voice data
    onError: (err, req, res) => {
      console.error(`Voice proxy error:`, err);
      res.status(502).json({ error: 'Proxy error', message: err.message });
    }
  });
  
  proxy(req, res, next);
});

// Group endpoints proxying
app.use('/api/:nodeId/groups', (req, res, next) => {
  const nodeId = req.params.nodeId;
  
  // Get node info based on nodeId
  const nodeInfo = KNOWN_NODES[nodeId];
  
  if (!nodeInfo) {
    return res.status(404).json({ 
      error: 'Node not found', 
      message: `Node ID '${nodeId}' is not registered with this proxy` 
    });
  }
  
  // Use API address for API calls
  const targetHost = nodeInfo.apiAddress;
  
  // Create a proxy for group endpoints
  const proxy = createProxyMiddleware({
    target: targetHost,
    changeOrigin: true,
    pathRewrite: {
      [`^/api/${nodeId}/groups`]: '/groups', // Remove the /api/nodeId prefix when forwarding
    },
    onProxyReq: (proxyReq, req, res) => {
      // Add custom headers
      proxyReq.setHeader('X-Forwarded-By', 'Subworld-Proxy');
      proxyReq.setHeader('X-Forwarded-Proto', 'https');
      
      // Log the proxied request if detailed logging is enabled
      if (ENABLE_DETAILED_LOGGING) {
        console.log(`Proxying group request to: ${targetHost}${req.path.replace(`/api/${nodeId}/groups`, '/groups')}`);
      }
    },
    onError: (err, req, res) => {
      console.error(`Proxy error for group request ${req.method} ${req.url}:`, err);
      res.status(502).json({ 
        error: 'Proxy error', 
        message: err.message,
        nodeId: nodeId,
        endpoint: req.path.replace(`/api/${nodeId}/groups`, '/groups')
      });
    }
  });
  
  proxy(req, res, next);
});

// Special endpoint for Subworld Node API endpoints
app.use('/subworld/:endpoint', (req, res, next) => {
  // Default to bootstrap node for these calls
  const nodeId = 'bootstrap1';
  const nodeInfo = KNOWN_NODES[nodeId];
  
  if (!nodeInfo) {
    return res.status(500).json({ 
      error: 'Configuration error', 
      message: 'Bootstrap node not configured' 
    });
  }
  
  // Target the API of the bootstrap node
  const targetHost = nodeInfo.apiAddress;
  const endpoint = req.params.endpoint;
  
  // Create a proxy specifically for these endpoints
  const proxy = createProxyMiddleware({
    target: targetHost,
    changeOrigin: true,
    pathRewrite: {
      [`^/subworld/${endpoint}`]: `/${endpoint}`, // Rewrite to the actual endpoint
    },
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('X-Forwarded-By', 'Subworld-Proxy');
      proxyReq.setHeader('X-Forwarded-Proto', 'https');
    },
    onError: (err, req, res) => {
      console.error(`Subworld proxy error for ${req.method} ${req.url}:`, err);
      res.status(502).json({ error: 'Proxy error', message: err.message });
    }
  });
  
  proxy(req, res, next);
});

// Handle default route
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    message: 'The requested resource does not exist on this server'
  });
});


// Track connected users by their public key
const connectedUsers = new Map();
const activeCallSessions = new Map();

io.on('connection', (socket) => {
  console.log('New socket connection:', socket.id);
  
  // User registers with their public key
  socket.on('register', (data) => {
    const { publicKey } = data;
    if (!publicKey) return;
    
    console.log(`User registered: ${publicKey} with socket ID: ${socket.id}`);
    connectedUsers.set(publicKey, socket.id);
    
    // Send confirmation to client
    socket.emit('registered', { success: true });
    
    // Clean up on disconnect
    socket.on('disconnect', () => {
      console.log(`User disconnected: ${publicKey}`);
      connectedUsers.delete(publicKey);
      
      // End any active calls
      for (const [callId, call] of activeCallSessions.entries()) {
        if (call.caller === publicKey || call.recipient === publicKey) {
          // Notify the other party that the call ended
          const otherParty = call.caller === publicKey ? call.recipient : call.caller;
          const otherSocket = io.sockets.sockets.get(connectedUsers.get(otherParty));
          
          if (otherSocket) {
            otherSocket.emit('call_ended', { callId });
          }
          
          activeCallSessions.delete(callId);
        }
      }
    });
  });
  
  // Call signaling
  socket.on('call_request', (data) => {
    const { callId, caller, recipient } = data;
    console.log(`Call request from ${caller} to ${recipient}, callId: ${callId}`);
    
    const recipientSocketId = connectedUsers.get(recipient);
    if (!recipientSocketId) {
      // Recipient not connected
      socket.emit('call_status', { 
        callId, 
        status: 'failed', 
        reason: 'recipient_offline'
      });
      return;
    }
    
    // Store call session
    activeCallSessions.set(callId, {
      caller,
      recipient,
      startTime: new Date().toISOString(),
      status: 'ringing'
    });
    
    // Notify recipient
    const recipientSocket = io.sockets.sockets.get(recipientSocketId);
    if (recipientSocket) {
      recipientSocket.emit('incoming_call', {
        callId,
        caller,
        timestamp: new Date().toISOString()
      });
      
      // Tell caller we're ringing the recipient
      socket.emit('call_status', { callId, status: 'ringing' });
    } else {
      socket.emit('call_status', { callId, status: 'failed', reason: 'delivery_failed' });
      activeCallSessions.delete(callId);
    }
  });
  
  // Call response (accept/reject)
  socket.on('call_response', (data) => {
    const { callId, response, recipient, caller } = data;
    console.log(`Call response for ${callId}: ${response}`);
    
    const callSession = activeCallSessions.get(callId);
    if (!callSession) {
      console.log(`No active call session found for ${callId}`);
      socket.emit('call_status', { callId, status: 'failed', reason: 'invalid_call_id' });
      return;
    }
    
    // Update call status
    callSession.status = response === 'accepted' ? 'active' : 'rejected';
    activeCallSessions.set(callId, callSession);
    
    // Get caller socket
    const callerSocketId = connectedUsers.get(caller);
    if (!callerSocketId) {
      socket.emit('call_status', { callId, status: 'failed', reason: 'caller_offline' });
      activeCallSessions.delete(callId);
      return;
    }
    
    const callerSocket = io.sockets.sockets.get(callerSocketId);
    if (!callerSocket) {
      socket.emit('call_status', { callId, status: 'failed', reason: 'caller_disconnected' });
      activeCallSessions.delete(callId);
      return;
    }
    
    // Notify caller of response
    callerSocket.emit('call_response', {
      callId,
      response,
      recipient
    });
    
    if (response === 'rejected') {
      activeCallSessions.delete(callId);
    }
  });
  
  // WebRTC signaling between peers
  socket.on('peer_signal', (data) => {
    const { signal, callId, sender, recipient } = data;
    console.log(`Signal for call ${callId} from ${sender} to ${recipient}`);
    
    const recipientSocketId = connectedUsers.get(recipient);
    if (!recipientSocketId) {
      socket.emit('signal_status', { callId, status: 'failed', reason: 'recipient_offline' });
      return;
    }
    
    const recipientSocket = io.sockets.sockets.get(recipientSocketId);
    if (recipientSocket) {
      recipientSocket.emit('peer_signal', {
        signal,
        callId,
        sender
      });
    }
  });
  
  // End call
  socket.on('end_call', (data) => {
    const { callId, userId } = data;
    console.log(`End call request for ${callId} from ${userId}`);
    
    const callSession = activeCallSessions.get(callId);
    if (!callSession) {
      console.log(`No active call session found for ${callId}`);
      return;
    }
    
    // Get other participant
    const otherParty = callSession.caller === userId ? callSession.recipient : callSession.caller;
    const otherSocketId = connectedUsers.get(otherParty);
    
    if (otherSocketId) {
      const otherSocket = io.sockets.sockets.get(otherSocketId);
      if (otherSocket) {
        otherSocket.emit('call_ended', { callId, by: userId });
      }
    }
    
    // Remove the call session
    activeCallSessions.delete(callId);
  });
});

// Start the server
server.listen(PORT, HOST, () => {
  console.log(`Subworld Network Proxy running on ${HOST}:${PORT}`);
  console.log(`Socket.io signaling server enabled`);
  console.log(`TURN server running on port ${TURN_PORT}`);
  console.log(`Detailed logging: ${ENABLE_DETAILED_LOGGING ? 'Enabled' : 'Disabled'}`);
  console.log(`Available nodes: ${Object.keys(KNOWN_NODES).join(', ')}`);
});