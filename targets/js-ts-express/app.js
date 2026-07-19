// Entry point: mounts all routers (overview of all HTTP entrypoints).
const express = require('express');

const usersRouter = require('./routes/users');
const adminRouter = require('./routes/admin');
const filesRouter = require('./routes/files');
const toolsRouter = require('./routes/tools');
const xmlRouter = require('./routes/xml');
const renderRouter = require('./routes/render');
const authRouter = require('./routes/auth');
const ordersRouter = require('./routes/orders');
const profileRouter = require('./routes/profile');

const app = express();
app.use(express.json());
app.use(express.text({ type: ['text/*', 'application/xml'] }));

app.use('/users', usersRouter);
app.use('/admin', adminRouter);
app.use('/files', filesRouter);
app.use('/tools', toolsRouter);
app.use('/xml', xmlRouter);
app.use('/render', renderRouter);
app.use('/auth', authRouter);
app.use('/orders', ordersRouter);
app.use('/profile', profileRouter);

app.listen(3000, () => console.log('listening on :3000'));
