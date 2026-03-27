import { AppError } from './errors';
import { logger } from '../lib/logger';

/**
 * A resilient wrapper around the native Node.js fetch API.
 * Safely intercepts network-level crashes (like ECONNREFUSED when a microservice is down)
 * and transforms them into graceful, industry-standard 503 AppErrors.
 */
export async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (err) {
    const error = err as { message?: string; cause?: { code?: string } };
    // Undici (Node's native fetch) throws a TypeError with an AggregateError cause for connection drops
    if (error?.message?.includes('fetch failed') || error?.cause?.code === 'ECONNREFUSED') {
      logger.error({ url, err: error }, 'Internal Microservice Unreachable (ECONNREFUSED)');
      throw new AppError(
        'SERVICE_UNAVAILABLE',
        503,
        'The requested internal service is currently offline or unreachable. Please try again later.'
      );
    }
    
    // Fallback for other catastrophic fetch-level exceptions
    logger.error({ url, err: error }, 'Unexpected Internal Fetch Error');
    throw new AppError('INTERNAL_ERROR', 500, 'An unexpected error occurred during internal communication.');
  }
}
