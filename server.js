const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { analyzeFile } = require('./lib/analyzer');

const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: 100 * 1024 * 1024 },
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' });
  res.json({
    jobId: req.file.filename,
    originalName: req.file.originalname,
    size: req.file.size,
  });
});

app.get('/analyze/:jobId', (req, res) => {
  const { jobId } = req.params;
  const { name, size } = req.query;
  const filePath = path.join(__dirname, 'uploads', jobId);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const emit = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  analyzeFile(filePath, name || jobId, Number(size) || 0, emit)
    .then(() => {
      emit('done', {});
      res.end();
      fs.unlink(filePath, () => {});
    })
    .catch((err) => {
      emit('error', { message: err.message });
      res.end();
      fs.unlink(filePath, () => {});
    });
});

// Create uploads dir if missing
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'uploads'));
}

app.listen(PORT, () => {
  console.log(`bin.ary running at http://localhost:${PORT}`);
});
