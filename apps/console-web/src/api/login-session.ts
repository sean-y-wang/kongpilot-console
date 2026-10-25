import { api, ApiError, awaitPendingSessionRefresh, beginSessionTransition, post, setApiActorId, setCsrfToken } from './client';
import type { Session } from './types';

let loggingIn = false;
export async function loadLoginSession(path: string, body: { username: string; password: string }): Promise<Session> {
  if (loggingIn) throw new ApiError('登录请求仍在处理中，请等待完成。', 409, 'LOGIN_IN_PROGRESS');
  loggingIn = true;
  const finishTransition = beginSessionTransition();
  try {
    // Let an older refresh's Set-Cookie finish before issuing the new account login.
    await awaitPendingSessionRefresh();
    const loggedIn = await post<Session>(path, body);
    setCsrfToken(loggedIn.csrfToken);
    const current = await api<Session>('/auth/me');
    if (!loggedIn.user?.id || current.user?.id !== loggedIn.user.id) {
      throw new ApiError('登录会话的账号已变化，请重新登录。', 401, 'SESSION_CHANGED');
    }
    setApiActorId(current.user.id);
    setCsrfToken(current.csrfToken);
    return current;
  } finally { loggingIn = false; finishTransition(); }
}
