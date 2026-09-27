package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.config.PolicyProperties;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicySet;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 本地策略来源：配置了 depaudit.policy.file 则从该本地文件加载；
 * 否则加载 classpath 内置默认策略。启动时一次性加载并缓存，
 * 保证同批次/重复执行期间策略版本不变、结论一致。
 */
@Component
public class LocalPolicyProvider implements PolicyProvider {

    public static final String DEFAULT_CLASSPATH_POLICY = "default-policy.json";

    private final PolicyProperties properties;
    private final LocalPolicyLoader loader;
    private volatile PolicySet cached;

    public LocalPolicyProvider(PolicyProperties properties, LocalPolicyLoader loader) {
        this.properties = properties;
        this.loader = loader;
    }

    @Override
    public PolicySet current() {
        PolicySet snapshot = cached;
        if (snapshot == null) {
            synchronized (this) {
                if (cached == null) {
                    cached = load();
                }
                snapshot = cached;
            }
        }
        return snapshot;
    }

    private PolicySet load() {
        String configured = properties.getFile();
        if (configured != null && !configured.isBlank()) {
            Path path = Path.of(configured);
            if (!Files.exists(path)) {
                throw new PolicyLoadException(
                        "configured policy file does not exist: " + path);
            }
            return loader.load(path);
        }
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream(DEFAULT_CLASSPATH_POLICY)) {
            if (in == null) {
                throw new PolicyLoadException(
                        "built-in policy resource missing: " + DEFAULT_CLASSPATH_POLICY);
            }
            return loader.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new PolicyLoadException("failed to read built-in policy", e);
        }
    }
}
