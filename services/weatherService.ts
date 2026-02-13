import type { HttpClient } from "../utils/httpClient";

export interface WeatherInfo {
    location: string;
    temp_f: number;
    condition: string;
}

export interface ForecastDay {
    date: string;
    maxTempF: number;
    minTempF: number;
    condition: string;
}

export interface DetailedForecastDay extends ForecastDay {
    sunrise: string;
    sunset: string;
    humidity: number;
    precipitation: number;
    windSpeed: number;
    windDirection: string;
    chanceOfRain: number;
    uvIndex: number;
    hourlyForecast?: HourlyForecast[];
}

export interface HourlyForecast {
    time: string;
    tempF: number;
    condition: string;
    windSpeed: number;
    chanceOfRain: number;
    feelsLike: number;
}

export interface WeatherAlert {
    alertType: string;
    severity: string;
    headline: string;
    message: string;
    effective: string;
    expires: string;
    areas: string;
}

export interface AirQuality {
    location: string;
    aqi: number;
    co: number;
    no2: number;
    o3: number;
    so2: number;
    pm2_5: number;
    pm10: number;
    usEpaIndex: number;
}

export interface IWeatherService {
    getCurrentWeatherByCoords(latitude: number, longitude: number): Promise<WeatherInfo>;
    get7DayForecastByCoords(latitude: number, longitude: number): Promise<ForecastDay[]>;
    get7DayForecastByLocation(location: string): Promise<ForecastDay[]>;
    getHourlyForecast(location: string, days?: number): Promise<HourlyForecast[]>;
    getDetailedForecast(location: string, days?: number): Promise<DetailedForecastDay[]>;
    getWeatherAlerts(location: string): Promise<WeatherAlert[]>;
    getAirQuality(location: string): Promise<AirQuality>;
    getAstronomy(location: string, date?: string): Promise<any>;
    getHistoricalWeather(location: string, date: string): Promise<any>;
    getFutureWeather(location: string, date: string): Promise<any>;
}

interface CurrentApiResponse {
    location: { name: string };
    current: {
        temp_f: number;
        condition: { text: string };
        wind_mph: number;
        wind_dir: string;
        humidity: number;
        feelslike_f: number;
        uv: number;
        air_quality?: any;
    };
}

interface ForecastApiResponse {
    forecast: {
        forecastday: Array<{
            date: string;
            day: {
                maxtemp_f: number;
                mintemp_f: number;
                condition: { text: string };
                daily_chance_of_rain: number;
                avghumidity: number;
                totalprecip_in: number;
                maxwind_mph: number;
                uv: number;
            };
            astro: {
                sunrise: string;
                sunset: string;
            };
            hour: Array<{
                time: string;
                temp_f: number;
                condition: { text: string };
                wind_mph: number;
                chance_of_rain: number;
                feelslike_f: number;
            }>;
        }>;
    };
}

interface AlertsApiResponse {
    alerts: {
        alert: Array<{
            headline: string;
            msgtype: string;
            severity: string;
            desc: string;
            effective: string;
            expires: string;
            areas: string;
        }>;
    };
}

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signProxyRequest(secret: string, payload: string): Promise<string> {
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
    return toBase64Url(new Uint8Array(sig));
}

export class WeatherApiService implements IWeatherService {
    private readonly baseUrl = "https://api.weatherapi.com/v1";

    constructor(
        private readonly http: HttpClient,
        private readonly apiKey: string,
        private readonly proxyBaseUrl?: string,
        private readonly proxyBearerToken?: string,
        private readonly proxySigningSecret?: string
    ) { }

    private async weatherGet<T>(endpoint: string, params: Record<string, string | number>): Promise<T> {
        if (this.proxyBaseUrl) {
            const proxyUrl = new URL(`/weatherapi/${endpoint.replace(/^\//, "")}`, this.proxyBaseUrl);
            for (const [k, v] of Object.entries(params)) {
                proxyUrl.searchParams.set(k, String(v));
            }

            const headers: Record<string, string> = {};
            if (this.proxyBearerToken) {
                headers["Authorization"] = `Bearer ${this.proxyBearerToken}`;
            }
            if (this.proxySigningSecret) {
                const ts = Math.floor(Date.now() / 1000).toString();
                const signingPayload = `${ts}.GET.${proxyUrl.pathname}${proxyUrl.search}`;
                headers["X-Proxy-Timestamp"] = ts;
                headers["X-Proxy-Signature"] = await signProxyRequest(this.proxySigningSecret, signingPayload);
            }

            return this.http.get<T>(proxyUrl.toString(), {
                headers,
            });
        }

        const url = new URL(`${this.baseUrl}/${endpoint.replace(/^\//, "")}`);
        url.searchParams.set("key", this.apiKey);
        for (const [k, v] of Object.entries(params)) {
            url.searchParams.set(k, String(v));
        }
        return this.http.get<T>(url.toString());
    }

    async getCurrentWeatherByCoords(latitude: number, longitude: number): Promise<WeatherInfo> {
        const resp = await this.weatherGet<CurrentApiResponse>("current.json", { q: `${latitude},${longitude}` });
        return {
            location: resp.location.name,
            temp_f: resp.current.temp_f,
            condition: resp.current.condition.text,
        };
    }

    async get7DayForecastByCoords(latitude: number, longitude: number): Promise<ForecastDay[]> {
        const resp = await this.weatherGet<ForecastApiResponse>("forecast.json", {
            q: `${latitude},${longitude}`,
            days: 7,
        });
        return resp.forecast.forecastday.map((f) => ({
            date: f.date,
            maxTempF: f.day.maxtemp_f,
            minTempF: f.day.mintemp_f,
            condition: f.day.condition.text,
        }));
    }

    async get7DayForecastByLocation(location: string): Promise<ForecastDay[]> {
        const resp = await this.weatherGet<ForecastApiResponse>("forecast.json", {
            q: location,
            days: 7,
        });
        return resp.forecast.forecastday.map((f) => ({
            date: f.date,
            maxTempF: f.day.maxtemp_f,
            minTempF: f.day.mintemp_f,
            condition: f.day.condition.text,
        }));
    }

    async getHourlyForecast(location: string, days: number = 1): Promise<HourlyForecast[]> {
        const resp = await this.weatherGet<ForecastApiResponse>("forecast.json", {
            q: location,
            days,
        });

        const hourlyForecasts: HourlyForecast[] = [];

        for (const day of resp.forecast.forecastday) {
            for (const hour of day.hour) {
                hourlyForecasts.push({
                    time: hour.time,
                    tempF: hour.temp_f,
                    condition: hour.condition.text,
                    windSpeed: hour.wind_mph,
                    chanceOfRain: hour.chance_of_rain,
                    feelsLike: hour.feelslike_f,
                });
            }
        }

        return hourlyForecasts;
    }

    async getDetailedForecast(location: string, days: number = 7): Promise<DetailedForecastDay[]> {
        const resp = await this.weatherGet<ForecastApiResponse>("forecast.json", {
            q: location,
            days,
        });

        return resp.forecast.forecastday.map((f) => ({
            date: f.date,
            maxTempF: f.day.maxtemp_f,
            minTempF: f.day.mintemp_f,
            condition: f.day.condition.text,
            sunrise: f.astro.sunrise,
            sunset: f.astro.sunset,
            humidity: f.day.avghumidity,
            precipitation: f.day.totalprecip_in,
            windSpeed: f.day.maxwind_mph,
            windDirection: "N/A",
            chanceOfRain: f.day.daily_chance_of_rain,
            uvIndex: f.day.uv,
            hourlyForecast: f.hour.map((h) => ({
                time: h.time,
                tempF: h.temp_f,
                condition: h.condition.text,
                windSpeed: h.wind_mph,
                chanceOfRain: h.chance_of_rain,
                feelsLike: h.feelslike_f,
            })),
        }));
    }

    async getWeatherAlerts(location: string): Promise<WeatherAlert[]> {
        const resp = await this.weatherGet<ForecastApiResponse & AlertsApiResponse>("forecast.json", {
            q: location,
            days: 1,
            alerts: "yes",
        });

        if (!resp.alerts || !resp.alerts.alert) {
            return [];
        }

        return resp.alerts.alert.map((alert) => ({
            alertType: alert.msgtype,
            severity: alert.severity,
            headline: alert.headline,
            message: alert.desc,
            effective: alert.effective,
            expires: alert.expires,
            areas: alert.areas,
        }));
    }

    async getAirQuality(location: string): Promise<AirQuality> {
        const resp = await this.weatherGet<CurrentApiResponse>("current.json", {
            q: location,
            aqi: "yes",
        });

        const airQuality = resp.current.air_quality || {};

        return {
            location: resp.location.name,
            aqi: airQuality.air_quality_index || 0,
            co: airQuality.co || 0,
            no2: airQuality.no2 || 0,
            o3: airQuality.o3 || 0,
            so2: airQuality.so2 || 0,
            pm2_5: airQuality.pm2_5 || 0,
            pm10: airQuality.pm10 || 0,
            usEpaIndex: airQuality["us-epa-index"] ?? airQuality.usEpaIndex ?? 0,
        };
    }

    async getAstronomy(location: string, date?: string): Promise<any> {
        const dateParam = date || new Date().toISOString().split("T")[0];
        const resp = await this.weatherGet<{ astronomy: { astro: any } }>("astronomy.json", {
            q: location,
            dt: dateParam,
        });

        return resp.astronomy.astro;
    }

    async getHistoricalWeather(location: string, date: string): Promise<any> {
        return this.weatherGet<any>("history.json", { q: location, dt: date });
    }

    async getFutureWeather(location: string, date: string): Promise<any> {
        return this.weatherGet<any>("future.json", { q: location, dt: date });
    }
}
