export const required = (): never => {
  throw new Error('A required value was not provided')
}
