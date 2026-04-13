from __future__ import annotations
import hashlib
import logging
import re
from typing import Optional, Tuple
from datetime import datetime, timedelta, UTC
from uuid import UUID
from fastapi import Request, HTTPException
from pydantic import validator

from ..repositories.session import SessionRepository
from ..models.session import Session
from .security import SecurityService

# Logging
logger = logging.getLogger(__name__)

try:
    from ua_parser import user_agent_parser
    UA_PARSER_AVAILABLE = True
except ImportError:
    UA_PARSER_AVAILABLE = False
    logger.warning("ua-parser not available")

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("geoip2 not available")


class SessionService:
    def __init__(self, db, cache, env: dict, geoip_db_path: str | None = None):
        self.db = db
        self.cache = cache
        self.env = env
        self._security = SecurityService(env["ENCRYPTION_KEY"])
        
        # GeoIP setup
        self._geoip_reader = None
        if geoip_db_path and GEOIP_AVAILABLE:
            try:
                self._geoip_reader = geoip2.database.Reader(geoip_db_path)
                logger.info(f"GeoIP database loaded: {geoip_db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
                self._geoip_reader = None

    def _repo(self, session) -> SessionRepository:
        return SessionRepository(session)

    def _validate_ip(self, ip: str) -> str:
        """Valide et nettoie l'IP, retourne 0.0.0.0 si invalide"""
        if not ip:
            return "0.0.0.0"
        
        # Support IPv4 et IPv6 basique
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        ipv6_pattern = r'^[0-9a-fA-F:]+$'
        
        if re.match(ipv4_pattern, ip.strip()) or re.match(ipv6_pattern, ip.strip()):
            return ip.strip()
        return "0.0.0.0"

    def _extract_ip(self, request: Request) -> str:
        """Extrait l'IP réelle même derrière un proxy"""
        # X-Forwarded-For (premier IP = client réel)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
            logger.debug(f"X-Forwarded-For IP: {ip}")
            return self._validate_ip(ip)
        
        # CF-Connecting-IP (Cloudflare)
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            logger.debug(f"Cloudflare IP: {cf_ip}")
            return self._validate_ip(cf_ip)
        
        # Client direct
        if request.client:
            ip = request.client.host
            logger.debug(f"Direct client IP: {ip}")
            return self._validate_ip(ip)
        
        logger.warning("No valid IP found")
        return "0.0.0.0"

    def _parse_user_agent(self, ua: str) -> dict:
        """Parse l'User-Agent si disponible"""
        if not ua or not UA_PARSER_AVAILABLE:
            return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}
        
        try:
            parsed = user_agent_parser.Parse(ua)
            return {
                "browser": parsed["family"],
                "os": parsed["os"]["family"],
                "device": parsed["device"]["family"]
            }
        except Exception as e:
            logger.debug(f"UA parsing failed: {e}")
            return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}

    def _parse_geo(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse la géolocalisation avec GeoIP2"""
        if not ip or ip == "0.0.0.0" or not self._geoip_reader:
            return None, None
        
        try:
            response = self._geoip_reader.city(ip)
            country = response.country.iso_code
            city = response.city.name
            logger.debug(f"GeoIP {ip}: {country}/{city}")
            return country, city
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return None, None

    async def create_session(
        self,
        user_id: UUID,
        request: Request,
        refresh_token: str,
        expires_in: int = 7 * 24 * 3600,  # 7 jours par défaut
        
    ) -> Session:
        """Crée une nouvelle session avec tous les métadonnées"""
        if expires_in <= 0:
            raise HTTPException(status_code=400, detail="expires_in must be positive")
        
        ip = self._extract_ip(request)
        ua = request.headers.get("User-Agent", "")
        ua_info = self._parse_user_agent(ua)
        geo_country, geo_city = self._parse_geo(ip)
        
        # Fingerprint unique
        fingerprint = self._security.fingerprint(
            ip=ip,
            ua=ua,
            ua_browser=ua_info["browser"],
            ua_os=ua_info["os"],
            ua_device=ua_info["device"],
            geo_country=geo_country
        )
        
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        
        async with self.db.session() as session:
            try:
                new_session = await self._repo(session).create(
                    user_id=user_id,
                    refresh_token_hash=token_hash,
                    expires_at=expires_at,
                    ip_address=ip,
                    user_agent=ua[:500],  # Limite la taille
                    user_agent_info=ua_info,
                    device_fingerprint=fingerprint,
                    geo_country=geo_country,
                    geo_city=geo_city,
                )
                logger.info(f"Session created for user {user_id}: {new_session.id}")
                
                # Cache la session (5min TTL)
                await self._cache_session(new_session)
                
                return new_session
            except Exception as e:
                logger.error(f"Failed to create session for {user_id}: {e}")
                raise HTTPException(status_code=500, detail="Session creation failed")

    async def get_by_refresh_token(self, refresh_token: str) -> Optional[Session]:
        """Récupère une session par refresh token (avec cache)"""
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        cache_key = f"session:token:{token_hash}"
        
        # Cache lookup
        cached = await self.cache.get(cache_key)
        if cached:
            session = Session.from_dict(cached)  # À adapter selon ton modèle
            if session and not session.is_expired:
                logger.debug(f"Session {session.id} found in cache")
                return session
        
        # DB lookup
        async with self.db.session() as session:
            db_session = await self._repo(session).get_by_token_hash(token_hash)
            if db_session and not db_session.is_expired:
                await self._cache_session(db_session)
                return db_session
            
            logger.debug(f"No valid session found for token {token_hash[:16]}...")
            return None

    async def revoke_session(
        self,
        session_id: UUID,
        reason: str | None = None,
    ) -> None:
        """Révoque une session spécifique"""
        async with self.db.session() as session:
            sess = await self._repo(session).get_by_id(session_id)
            if not sess:
                raise HTTPException(status_code=404, detail="Session not found")
            
            await self._repo(session).revoke(sess, reason)
            await self._invalidate_cache(sess)
            logger.info(f"Session {session_id} revoked: {reason or 'no reason'}")

    async def revoke_all_user_sessions(
        self,
        user_id: UUID,
        except_session_id: UUID | None = None,
    ) -> int:
        """Révoque toutes les sessions d'un user (sauf une)"""
        async with self.db.session() as session:
            count = await self._repo(session).revoke_all_user_sessions(user_id, except_session_id)
            logger.info(f"Revoked {count} sessions for user {user_id}")
            return count

    async def list_user_sessions(
        self, 
        user_id: UUID, 
        current_session_id: UUID | None = None
    ) -> list[Session]:
        """Liste toutes les sessions d'un user"""
        cache_key = f"sessions:user:{user_id}"
        
        # Cache lookup
        cached = await self.cache.get(cache_key)
        if cached:
            sessions = [Session.from_dict(s) for s in cached]
        else:
            # DB lookup
            async with self.db.session() as session:
                sessions = await self._repo(session).list_user_sessions(user_id)
                # Cache pour 1min
                await self.cache.setex(cache_key, 60, [s.to_dict() for s in sessions])
        
        # Marque la session courante
        if current_session_id:
            for s in sessions:
                s.is_current = (str(s.id) == str(current_session_id))
        
        return sessions

    async def touch(self, session: Session) -> None:
        """Met à jour le last_activity d'une session"""
        async with self.db.session() as sess:
            await self._repo(sess).touch(session)
            await self._cache_session(session)
            logger.debug(f"Session {session.id} touched")

    async def cleanup_expired_sessions(self) -> int:
        """Nettoie les sessions expirées (cron job)"""
        async with self.db.session() as session:
            count = await self._repo(session).cleanup_expired()
            logger.info(f"Cleaned up {count} expired sessions")
            return count

    # === Helpers privés ===
    async def _cache_session(self, session: Session, ttl: int = 300) -> None:
        """Cache une session"""
        cache_key = f"session:{session.id}"
        await self.cache.setex(cache_key, ttl, session.to_dict())

    async def _invalidate_cache(self, session: Session) -> None:
        """Invalide le cache d'une session"""
        cache_keys = [
            f"session:{session.id}",
            f"session:token:{session.refresh_token_hash}",
            f"sessions:user:{session.user_id}"
        ]
        for key in cache_keys:
            await self.cache.delete(key)