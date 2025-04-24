const ipSuspicionCount = new Map();

export function incrementSuspicion(ip) {
  const current = ipSuspicionCount.get(ip) || 0;
  ipSuspicionCount.set(ip, current + 1);
  return ipSuspicionCount.get(ip);
}

export function resetSuspicion(ip) {
  ipSuspicionCount.delete(ip);
}

export function getSuspicion(ip) {
  return ipSuspicionCount.get(ip) || 0;
}
