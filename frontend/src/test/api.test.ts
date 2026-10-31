import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, getToken } from '@/lib/api';

describe('getToken', () => {
  beforeEach(() => localStorage.clear());

  it('returns null when nothing stored', () => {
    expect(getToken()).toBeNull();
  });

  it('returns token from stored auth user', () => {
    localStorage.setItem('aiids.auth', JSON.stringify({ token: 'jwt-token-abc', role: 'admin' }));
    expect(getToken()).toBe('jwt-token-abc');
  });

  it('returns null on corrupt JSON', () => {
    localStorage.setItem('aiids.auth', '{not json');
    expect(getToken()).toBeNull();
  });
});

describe('ApiError', () => {
  it('carries status and message', () => {
    const e = new ApiError(403, 'forbidden');
    expect(e.status).toBe(403);
    expect(e.message).toBe('forbidden');
    expect(e).toBeInstanceOf(Error);
  });
});

// fetch-level behavior: 401 redirect handling (smoke via fetch mock)
describe('api request error mapping', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('throws ApiError with server detail on non-2xx', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ detail: 'Dataset not found' }), { status: 404 })));
    const { api } = await import('@/lib/api');
    await expect(api.get('/datasets/xyz')).rejects.toMatchObject({
      status: 404,
      message: 'Dataset not found',
    });
  });

  it('parses JSON on 200', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ items: [1, 2] }), { status: 200 })));
    const { api } = await import('@/lib/api');
    const body = await api.get<{ items: number[] }>('/alerts');
    expect(body.items).toEqual([1, 2]);
  });
});
