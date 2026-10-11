import serverless from 'serverless-http';
import { app } from '../../server/app.js';

// Cold-start: warm up the DB pool
let ready = false;
async function ensureReady() {
  if (ready) return;
  const { ping } = await import('../../server/db.js');
  await ping();
  ready = true;
}

const serverlessHandler = serverless(app, {
  binary: ['image/*', 'video/*', 'application/octet-stream']
});

export const handler = async (event, context) => {
  // Don't wait for empty event loop
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    await ensureReady();
    return await serverlessHandler(event, context);
  } catch (err) {
    console.error('[api] cold start failed', err);
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'internal_error' })
    };
  }
};
