import { defineStackbitConfig } from '@stackbit/sdk';
export default defineStackbitConfig({
  stackbitVersion: '~0.6.0',
  modelExtensions: [{ name: 'page', type: 'page', urlPath: '/:slug' }],
  contentSources: [],
});
