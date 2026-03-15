/// Define el ciclo de vida estándar para una sesión de captura ETW,
/// abstrayendo las diferencias entre sesiones de usuario y del kernel.
pub trait TraceSession: Send + Sync {
    /// Inicia la sesión de rastreo en el sistema operativo.
    /// Para UserTrace: Llama a StartTraceW y luego habilita proveedores.
    /// Para KernelTrace: Configura EnableFlags y llama a StartTraceW.
    fn start_session(&self) -> Result<(), String>;

    /// Inicia el bucle bloqueante de consumo de eventos.
    /// Esto envuelve la llamada a `ProcessTrace`.
    fn consume(&self) -> u32;

    /// Detiene la sesión y limpia los recursos, evitando que el
    /// sistema operativo deje sesiones huérfanas activas.
    fn stop_session(&self);
}
