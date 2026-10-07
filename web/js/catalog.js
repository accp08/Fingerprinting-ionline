// Catálogo didáctico: qué es cada atributo, por qué identifica y cómo defenderse.
// `ref` = bits de entropía aproximados reportados en estudios públicos
// (Panopticlick/EFF 2010, AmIUnique 2016, FP-Stalker 2018). Son órdenes de
// magnitud para comparar, no valores exactos.

window.CATEGORIES = {
  navegador:  { label: "Navegador",         icon: "🧭" },
  hardware:   { label: "Hardware",          icon: "💻" },
  pantalla:   { label: "Pantalla",          icon: "🖥️" },
  graficos:   { label: "Gráficos",          icon: "🎨" },
  audio:      { label: "Audio",             icon: "🔊" },
  fuentes:    { label: "Fuentes",           icon: "🔤" },
  region:     { label: "Idioma y región",   icon: "🌎" },
  privacidad: { label: "Privacidad",        icon: "🛡️" },
  red:        { label: "Red / HTTP",        icon: "🌐" },
};

window.CATALOG = {
  ua: {
    label: "User-Agent", cat: "navegador", ref: 10.0,
    what: "Texto que el navegador envía en cada petición describiendo navegador, versión y sistema operativo.",
    why: "Combina versión exacta del navegador y del sistema. Los navegadores poco actualizados o poco comunes quedan muy expuestos.",
    defense: "Mantener el navegador actualizado (estar en la versión más común). Chrome y Safari ya 'congelan' parte del UA (User-Agent Reduction).",
  },
  platform: {
    label: "Plataforma", cat: "navegador", ref: 2.3,
    what: "navigator.platform: familia del sistema operativo (MacIntel, Win32, Linux x86_64, iPhone…).",
    why: "Por sí sola dice poco, pero sirve para detectar contradicciones (ej. UA dice Windows y la plataforma dice Mac → navegador falsificado).",
    defense: "No se puede ocultar sin herramientas especiales; mentir aquí suele volverte MÁS único.",
  },
  vendor: {
    label: "Fabricante del navegador", cat: "navegador", ref: 1.0,
    what: "navigator.vendor: 'Google Inc.', 'Apple Computer, Inc.' o vacío (Firefox).",
    why: "Distingue motores de navegador aunque el User-Agent mienta.",
    defense: "Poco que hacer: es información del motor.",
  },
  webdriver: {
    label: "Automatización (bot)", cat: "navegador", ref: 0.1,
    what: "navigator.webdriver indica si el navegador lo controla un robot (Selenium, Puppeteer…).",
    why: "Los sistemas antifraude lo usan para detectar bots: un uso legítimo del fingerprinting.",
    defense: "Para un humano siempre es 'false'.",
  },
  plugins: {
    label: "Plugins / visor PDF", cat: "navegador", ref: 1.5,
    what: "Lista de plugins (navigator.plugins) y si existe visor de PDF integrado.",
    why: "En 2010 era el atributo más identificador (≈15 bits, por Flash y Java). Hoy los navegadores devuelven una lista fija, por eso aporta poco: ¡una defensa que funcionó!",
    defense: "Ya mitigado por los navegadores modernos.",
  },
  languages: {
    label: "Idiomas", cat: "region", ref: 5.9,
    what: "navigator.languages: lista de idiomas preferidos en orden.",
    why: "La combinación y el orden (es-CO, es, en-US…) es muy reveladora, sobre todo fuera de EE.UU.",
    defense: "Usar un solo idioma común (ej. solo 'en-US') reduce la entropía; Tor lo fuerza.",
  },
  timezone: {
    label: "Zona horaria", cat: "region", ref: 3.0,
    what: "Zona horaria del sistema (Intl) y su desfase respecto a UTC.",
    why: "Revela ubicación aproximada aunque uses VPN. Si la VPN dice 'Alemania' y la zona es 'America/Bogota', hay inconsistencia.",
    defense: "Firefox con privacy.resistFingerprinting y Tor reportan siempre UTC.",
  },
  intl: {
    label: "Formatos regionales", cat: "region", ref: 2.0,
    what: "Cómo el sistema formatea fechas, números y monedas, y su calendario.",
    why: "Configuraciones regionales personalizadas (ej. separador decimal distinto) te diferencian del resto.",
    defense: "Usar la configuración regional por defecto del sistema.",
  },
  screen: {
    label: "Resolución de pantalla", cat: "pantalla", ref: 4.8,
    what: "Tamaño total y disponible de la pantalla (descontando barras del sistema).",
    why: "Monitores poco comunes, múltiples pantallas o barras de tareas personalizadas generan combinaciones raras.",
    defense: "Tor usa 'letterboxing': redondea el tamaño de la ventana para que todos se parezcan.",
  },
  colorDepth: {
    label: "Profundidad de color", cat: "pantalla", ref: 1.0,
    what: "Bits por píxel de la pantalla (normalmente 24 o 30).",
    why: "Aporta poca información sola, pero suma en la combinación.",
    defense: "No requiere acción.",
  },
  pixelRatio: {
    label: "Densidad de píxeles", cat: "pantalla", ref: 2.0, volatile: true,
    what: "window.devicePixelRatio: relación entre píxeles físicos y lógicos (Retina = 2).",
    why: "Cambia con el ZOOM del navegador. Por eso no se usa para el ID: un rastreador real lo trata como dato volátil.",
    defense: "Mantener el zoom al 100 %.",
  },
  viewport: {
    label: "Tamaño de ventana", cat: "pantalla", ref: 5.0, volatile: true,
    what: "Tamaño interno de la ventana del navegador en este momento.",
    why: "Es muy único pero cambia al redimensionar, así que solo sirve para rastreo de corta duración.",
    defense: "Ventana maximizada o letterboxing (Tor).",
  },
  hardwareConcurrency: {
    label: "Núcleos de CPU", cat: "hardware", ref: 1.5,
    what: "navigator.hardwareConcurrency: número de núcleos lógicos del procesador.",
    why: "Separa equipos baratos (4) de estaciones de trabajo (16+).",
    defense: "Brave y Tor lo falsean o lo fijan en un valor común.",
  },
  deviceMemory: {
    label: "Memoria RAM", cat: "hardware", ref: 1.0,
    what: "navigator.deviceMemory: RAM aproximada en GB (solo Chrome/Edge, redondeada).",
    why: "Junto con los núcleos, perfila la gama del equipo.",
    defense: "Firefox y Safari no exponen esta API.",
  },
  touch: {
    label: "Pantalla táctil", cat: "hardware", ref: 1.0,
    what: "Número máximo de puntos táctiles y soporte de eventos touch.",
    why: "Distingue móviles, tabletas y laptops con pantalla táctil.",
    defense: "No requiere acción.",
  },
  canvas: {
    label: "Canvas fingerprint", cat: "graficos", ref: 8.3,
    what: "Se dibuja en un <canvas> invisible un texto con emojis y figuras, y se calcula el hash de los píxeles resultantes.",
    why: "El mismo dibujo produce píxeles ligeramente distintos según GPU, drivers, sistema, fuentes y antialiasing. ¡Es una de las técnicas más potentes y el usuario no ve nada!",
    defense: "Brave y Safari añaden ruido aleatorio; Firefox (resistFingerprinting) y Tor bloquean o piden permiso para leer el canvas.",
  },
  webglVendor: {
    label: "Tarjeta gráfica (WebGL)", cat: "graficos", ref: 3.4,
    what: "WebGL puede revelar el fabricante y el modelo exacto de la GPU.",
    why: "El modelo de GPU (ej. 'Apple M2', 'NVIDIA GeForce RTX 3060') es muy específico.",
    defense: "Firefox y Safari devuelven valores genéricos; se puede desactivar WebGL (rompe algunos sitios).",
  },
  webglParams: {
    label: "Capacidades WebGL", cat: "graficos", ref: 4.0,
    what: "Límites técnicos de la GPU: tamaño máximo de textura, extensiones soportadas, etc.",
    why: "Cada combinación GPU + driver + navegador tiene un 'perfil' distinto.",
    defense: "Igual que la anterior: navegadores con protección o WebGL desactivado.",
  },
  audio: {
    label: "Audio fingerprint", cat: "audio", ref: 5.4,
    what: "Se genera una onda de sonido SIN reproducirla, se procesa con un compresor y se suman las muestras.",
    why: "Diferencias de hardware y en la implementación de punto flotante producen un número distinto en cada equipo. Silencioso e invisible.",
    defense: "Brave añade ruido; Safari 17+ también lo aleatoriza en modo privado.",
  },
  fonts: {
    label: "Fuentes instaladas", cat: "fuentes", ref: 8.4,
    what: "Se mide el ancho de un texto con distintas fuentes: si cambia respecto a la fuente base, la fuente está instalada.",
    why: "Quien instala Office, Adobe, AutoCAD o fuentes de otros idiomas tiene una lista muy particular.",
    defense: "Safari y Tor solo exponen fuentes del sistema; evitar instalar fuentes innecesarias.",
  },
  voices: {
    label: "Voces de síntesis", cat: "audio", ref: 3.0,
    what: "Lista de voces de texto-a-voz disponibles (speechSynthesis).",
    why: "Depende del sistema operativo, sus idiomas instalados y versión.",
    defense: "Pocas defensas; Tor la desactiva.",
  },
  math: {
    label: "Motor matemático", cat: "navegador", ref: 1.0,
    what: "Resultado de funciones como Math.tan(-1e300) o Math.sinh(1).",
    why: "Los últimos decimales varían entre motores JavaScript y sistemas, revelando el navegador real.",
    defense: "No se puede cambiar.",
  },
  cookies: {
    label: "Cookies habilitadas", cat: "privacidad", ref: 0.3,
    what: "navigator.cookieEnabled.",
    why: "Casi todos las tienen activas; desactivarlas te hace minoría (¡más único!).",
    defense: "Paradoja: bloquear todo puede aumentar tu unicidad.",
  },
  dnt: {
    label: "Do Not Track / GPC", cat: "privacidad", ref: 0.9,
    what: "Señales de privacidad: Do Not Track y Global Privacy Control.",
    why: "Paradoja de la privacidad: activar DNT es un bit más que te distingue, y casi ningún sitio lo respeta.",
    defense: "GPC sí tiene respaldo legal en algunas jurisdicciones (ej. California).",
  },
  storage: {
    label: "Almacenamiento", cat: "privacidad", ref: 0.5,
    what: "Disponibilidad de localStorage, sessionStorage e IndexedDB.",
    why: "Algunos navegadores en modo privado los limitan, lo que delata el modo incógnito.",
    defense: "No requiere acción.",
  },
  mediaQueries: {
    label: "Preferencias visuales", cat: "pantalla", ref: 2.0,
    what: "Modo oscuro, reducir movimiento, alto contraste, tipo de puntero (ratón/dedo).",
    why: "Preferencias de accesibilidad poco comunes identifican mucho y además revelan información sensible.",
    defense: "Difícil: son necesarias para la accesibilidad.",
  },
  connection: {
    label: "Tipo de conexión", cat: "red", ref: 1.0, volatile: true,
    what: "navigator.connection: tipo efectivo de red (4g, 3g…) y ancho de banda estimado.",
    why: "Cambia con la red, así que es volátil, pero ayuda a perfilar contexto.",
    defense: "Firefox y Safari no exponen esta API.",
  },
  ip: {
    label: "Dirección IP", cat: "red", ref: 8.0, volatile: true, passive: true,
    what: "La IP desde la que te conectas. El servidor la ve SIEMPRE, sin ejecutar JavaScript.",
    why: "Fue el método clásico de rastreo, pero cambia (wifi, móvil, VPN) y se comparte (NAT). Por eso los rastreadores prefieren la huella.",
    defense: "VPN o Tor ocultan la IP… pero NO cambian tu huella del navegador.",
  },
  hAcceptLanguage: {
    label: "Cabecera Accept-Language", cat: "red", ref: 5.9, passive: true,
    what: "Cabecera HTTP con tus idiomas preferidos, enviada en CADA petición.",
    why: "Fingerprinting pasivo: el servidor la obtiene sin que tu navegador ejecute nada.",
    defense: "Configurar un único idioma común.",
  },
  hAcceptEncoding: {
    label: "Cabecera Accept-Encoding", cat: "red", ref: 1.0, passive: true,
    what: "Formatos de compresión que acepta el navegador (gzip, br, zstd…).",
    why: "Varía según navegador y versión: otra pista pasiva.",
    defense: "Mantener el navegador actualizado.",
  },
  hAccept: {
    label: "Cabecera Accept", cat: "red", ref: 1.0, passive: true,
    what: "Tipos de contenido que el navegador declara aceptar.",
    why: "Cada navegador tiene su cadena característica.",
    defense: "No requiere acción.",
  },
  hOrder: {
    label: "Orden de cabeceras HTTP", cat: "red", ref: 2.0, passive: true,
    what: "El ORDEN en que el navegador envía sus cabeceras HTTP.",
    why: "Cada navegador las ordena distinto: permite detectar si el User-Agent es falso.",
    defense: "No se puede cambiar desde el navegador.",
  },
};
