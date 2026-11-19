import * as z from 'zod';

export const summarizerQueryParams = z.object({
  key: z
    .string()
    .describe('The key is equal to value of field key as part of the Summarizer response model.'),
  entity_info: z
    .boolean()
    .default(false)
    .describe('Returns extra entities info with the summary response.')
    .optional(),
  inline_references: z
    .boolean()
    .default(false)
    .describe('Adds inline references to the summary response.')
    .optional(),
});

export type SummarizerQueryParams = z.infer<typeof summarizerQueryParams>;

export const chatCompletionsMessage = z.object({
  role: z
    .enum(['user'])
    .default('user')
    .describe('The role of the message. Only "user" is supported for now.'),
  content: z
    .string()
    .describe('The content of the message. The value is the question to be answered.'),
});

export type ChatCompletionsMessage = z.infer<typeof chatCompletionsMessage>;

export const chatCompletionParams = z.object({
  messages: z
    .array(chatCompletionsMessage)
    .describe(
      'The messages to use for the chat completion. The value is a list of ChatCompletionsMessage response models.'
    ),
  model: z
    .enum(['brave-pro', 'brave'])
    .default('brave-pro')
    .optional()
    .describe(
      'The model to use for the chat completion. The value can be "brave-pro" (default) or "brave".'
    ),
  stream: z
    .boolean()
    .default(true)
    .optional()
    .describe(
      'Whether to stream the response. The value is `true` by default. When using the OpenAI CLI, use `openai.AsyncOpenAI` for streaming and `openai.OpenAI` for blocking mode.'
    ),
  country: z
    .string()
    .default('us')
    .optional()
    .describe(
      'The country backend to use for the chat completion. The value is "us" by default. Note: This parameter is passed in extra_body field when using the OpenAI CLI.'
    ),
  language: z
    .string()
    .default('en')
    .optional()
    .describe(
      'The language to use for the chat completion. The value is "en" by default. Note: This parameter is passed in extra_body field when using the OpenAI CLI.'
    ),
  enable_entities: z
    .boolean()
    .default(false)
    .optional()
    .describe(
      'Whether to enable entities in the chat completion. The value is `false` by default. Note: This parameter is passed in extra_body field when using the OpenAI CLI.'
    ),
  enable_citations: z
    .boolean()
    .default(false)
    .optional()
    .describe(
      'Whether to enable citations in the chat completion. The value is `false` by default. Note: This parameter is passed in extra_body field when using the OpenAI CLI.'
    ),
});

export type ChatCompletionParams = z.infer<typeof chatCompletionParams>;
