package com.barbera.bestudy;

import static java.util.concurrent.CompletableFuture.runAsync;

import java.util.concurrent.CompletableFuture;

public class ThreadLocalApp {

    /*
    - Thread Per Request 모델과 ThreadLocal
    - Thread Per Request 모델 개요
        - WAS는 ThreadPool을 생성함 (Tomcat 기본값 200)
        - HTTP 요청이 들어오면 Queue에 적재되고, ThreadPool 내의 특정 Thread가 Queue에서 요청을 가져와 처리하게됨
        - HTTP 요청은 처음부터 끝까지 동일한 Thread에서 처리됨
        - HTTP 요청 처리가 끝나면 Thread는 다시 ThreadPool에 반납됨
        - 즉, WAS의 최대 동시 처리 HTTP 요청의 갯수는 ThreadPool의 갯수와 같음
        - Thead 갯수를 늘리면 동시 처리 갯수가 늘어나지만, Thread Context 스위칭에 의한 오버헤드도 커지기 때문에 성능이 선형적으로 증가하지는 않음
     */

    /**
     * Spring Web MVC는 Thread Per Request 모델을 기반으로 함
     * Thread Per Request 모델에서는 Client 요청을 처리하기 위해서 ThreadPool을 사용하고 있음
     * 동일 Thread내에서 실행되는 Controller, Service, Repository, 도메인 모델 어디에서든 명시적인 파라미터 전달 필요없이 ThreadLocal 변수에 접근할 수 있음
     * 따라서 Spring Web MVC에서 ThreadLocal 변수를 사용할때에는 Client 요청 처리가 모두 완료된 후에 ThreadLocal 변수를 반드시 삭제시켜 주어야 함
     * 그렇지 않을 경우, 요청 처리가 완료된 후에 Thread는 ThreadPool에 반환되기 때문에 이전 요청처리에서 사용된 ThreadLocal 변수가 남아
     *  다음 요청 처리 동작시 해당 변수가 참고되어 오류가 생길 수 있음.
     */

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    public static void main(String[] args) {
        System.out.println(getCurrentThreadName() + " ### main set value = 1 ");
        threadLocalValue.set(1);

        a();
        b();

        CompletableFuture<Void> task = runAsync(() -> {
            // Note: 해당 scope는 runAsync를 이용하여 메인스레드가 아닌 다른 스레드에서 실행되도록 함.
            a();
            b();
            // 출력 결과를 보면 1이 출력되지 않고 null이 출력됨
            // 즉, ThreadLocal 변수는 Thread마다 서로 독립적인 변수를 갖으며, Thread는 다른 Thread의 Local변수를 참조할 수 없다는 것을 의미.
        });
        task.join();

        // Note : ThreadLocal 변수는 사용후 반드시 삭제!
        threadLocalValue.remove();
    }

    public static void a() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() get value = " + value);
    }

    public static void b() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() get value = " + value);
    }

    public static String getCurrentThreadName() {
        return Thread.currentThread().getName();
    }

    /*
    SecurityContext는 ThreadLocal을 기반으로 동작하기 때문에, Spring Web MVC에서 Controller, Service, Repository, 도메인모델 어느 부분에서든
    SecurityContextHolder를 통해서 SecurityContext를 조회할 수 있다. (Spring Web MVC는 Thread Per Request기반으로 동작하기 때문)
     */
}
