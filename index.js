/**
 * Subworld Network Proxy
 * 
 * This proxy server acts as a secure bridge between HTTPS clients
 * and HTTP Subworld network nodes.
 */

const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');

// Configuration
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ENABLE_DETAILED_LOGGING = process.env.ENABLE_DETAILED_LOGGING === 'true' || false;

// Create Express app
const app = express();

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
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
      // For binary data like files, ensure content-type is preserved
      if (req.path.includes('/files/get')) {
        // Log content type for debugging
        console.log('File download content-type:', proxyRes.headers['content-type']);
        
        // Make sure we don't modify binary responses
        if (proxyRes.headers['content-type'] && 
            !proxyRes.headers['content-type'].includes('application/json')) {
          // Do not transform binary data
          delete proxyRes.headers['content-encoding'];
        }
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

// Start the server 
app.listen(PORT, HOST, () => {
  console.log(`Subworld Network Proxy running on ${HOST}:${PORT}`);
  console.log(`Detailed logging: ${ENABLE_DETAILED_LOGGING ? 'Enabled' : 'Disabled'}`);
  console.log(`Available nodes: ${Object.keys(KNOWN_NODES).join(', ')}`);
});