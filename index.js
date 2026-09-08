const path = require('path');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const authRouter = require('./auth');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api/auth', authRouter);

// 웹사이트(회원가입/로그인 포함)를 같은 서버에서 정적으로 서빙
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 4000;

db.init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Me+ 백엔드 서버가 실행됐어요: http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('DB 초기화 실패:', err);
    process.exit(1);
  });
