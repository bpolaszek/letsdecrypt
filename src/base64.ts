export function stringToBase64(str: string): string {
  return btoa(encodeURIComponent(str))
}

export function base64ToString(base64: string): string {
  return decodeURIComponent(atob(base64))
}
