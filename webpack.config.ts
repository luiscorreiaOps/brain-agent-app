import type { Configuration } from 'webpack';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';
import CopyWebpackPlugin from 'copy-webpack-plugin';
import ForkTsCheckerWebpackPlugin from 'fork-ts-checker-webpack-plugin';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const config = (_env: Record<string, string>): Configuration => ({
  context: join(__dirname, 'src'),
  entry: './module.tsx',
  mode: _env.production ? 'production' : 'development',
  // false in production (security-audit finding M-08 in the sibling
  // agent-ai-app repo, never applied here): a source map always generated,
  // even for a production build, exposed the full original TypeScript
  // source alongside the shipped bundle.
  devtool: _env.production ? false : 'source-map',
  output: {
    clean: true,
    filename: 'module.js',
    path: resolve(__dirname, 'dist'),
    publicPath: '',
    libraryTarget: 'amd',
    uniqueName: 'brain-agent',
  },
  externals: [
    'lodash',
    'react',
    'react-dom',
    'react/jsx-runtime',
    'react/jsx-dev-runtime',
    '@grafana/data',
    '@grafana/runtime',
    '@grafana/ui',
  ],
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: {
          loader: 'swc-loader',
        },
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        { from: 'plugin.json', to: '.' },
        { from: 'img/', to: 'img/' },
        { from: '../README.md', to: '.' },
        { from: '../LICENSE', to: '.' },
        { from: '../CHANGELOG.md', to: '.' },
      ],
    }),
    new ForkTsCheckerWebpackPlugin({
      async: Boolean(_env.development),
      typescript: { configFile: resolve(__dirname, 'tsconfig.json') },
    }),
  ],
});

export default config;
