import * as z from 'zod';

export const LocalPoisParams = z.object({
  ids: z.array(z.string()).describe('List of location IDs for which to fetch POIs'),
});

export const LocalDescriptionsParams = z.object({
  ids: z.array(z.string()).describe('List of location IDs for which to fetch descriptions'),
});

export type LocalPoisParams = z.infer<typeof LocalPoisParams>;
export type LocalDescriptionsParams = z.infer<typeof LocalDescriptionsParams>;
