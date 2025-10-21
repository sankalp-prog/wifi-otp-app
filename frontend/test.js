// import dotenv from 'dotenv';

// dotenv.config();

// console.log('Backend URL:', process.env.VITE_API_BASE_URL);

import { loadEnv } from 'vite';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const env = loadEnv('development', __dirname);
console.log(env.VITE_API_BASE_URL);
